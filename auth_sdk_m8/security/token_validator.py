"""Pure JWT validation helpers."""

from typing import Any

import jwt
from jwt import ExpiredSignatureError, InvalidSignatureError, PyJWTError
from pydantic import ValidationError

from auth_sdk_m8.authorization import (
    INCONSISTENT_PRIVILEGE_CLAIMS_REASON,
    find_inconsistent_privilege_claims_error,
)
from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.auth import TokenSecret, TokenUserData
from auth_sdk_m8.security.hooks import ValidationHooks
from auth_sdk_m8.security.key_resolver import KeyResolver, RefreshableKeyResolver
from auth_sdk_m8.security.validation import TokenValidationConfig

# Resolver failures that degrade to a plain token rejection instead of escaping
# to the caller.  Bound to a name rather than written inline: Ruff targets py314
# and rewrites an inline `except (A, B, C):` into PEP 758's parenthesis-free
# form, which is a SyntaxError on the 3.12 / 3.13 half of the support matrix.
_RESOLVER_ERRORS = (LookupError, TypeError, ValueError)


class TokenValidator:
    """Pure access-token validator with no I/O or storage dependencies.

    This validator is intentionally synchronous. Stateful or network-backed
    checks belong in a separate policy layer (``TokenPolicy``).

    Args:
        secrets: Static signing key. Mutually exclusive with *key_resolver*.
        config: Validation rules (algorithms, leeway, required claims, …).
        key_resolver: Dynamic key lookup keyed on the token ``kid`` header.
            Required when *secrets* is ``None``.  A resolver that also
            satisfies ``RefreshableKeyResolver`` gets one throttled re-resolve
            when a signature fails under a ``kid`` it just served, so a key
            replaced without a ``kid`` change recovers in a refresh interval
            rather than a full cache TTL.
        hooks: Optional observability callbacks for logging / metrics.
    """

    def __init__(
        self,
        secrets: TokenSecret | None,
        config: TokenValidationConfig,
        key_resolver: KeyResolver | None = None,
        hooks: ValidationHooks | None = None,
    ) -> None:
        self._default_secrets = secrets
        self._config = config
        self._key_resolver = key_resolver
        self._hooks = hooks

        if self._default_secrets is None and self._key_resolver is None:
            raise ValueError("Either secrets or key_resolver must be provided")

        if (
            self._default_secrets is not None
            and self._default_secrets.algorithm not in self._config.allowed_algorithms
        ):
            raise ValueError(
                "Algorithm "
                f"'{self._default_secrets.algorithm}' not allowed by configuration"
            )

    def validate_access_token(self, token: str) -> TokenUserData:
        """Decode and validate an access token.

        Args:
            token: Encoded JWT string.

        Returns:
            Parsed and validated ``TokenUserData``.

        Raises:
            InvalidToken: Token expired, invalid, wrong type, malformed, or
                carrying inconsistent privilege claims.
        """
        secrets, kid = self._resolve_secrets(token)
        payload = self._decode_payload(token, secrets, kid)

        if payload.get("type") != "access":
            if self._hooks:
                self._hooks.on_failure(reason="wrong_type", token_type="access")  # nosec B106
            raise InvalidToken("Not an access token")

        try:
            result = TokenUserData(**payload)
        except ValidationError as ex:
            mismatch = find_inconsistent_privilege_claims_error(ex)
            if mismatch is not None:
                if self._hooks:
                    self._hooks.on_failure(
                        reason=INCONSISTENT_PRIVILEGE_CLAIMS_REASON,
                        token_type="access",  # nosec B106
                    )
                # Chain the bounded reason, never the ValidationError — the
                # latter embeds the raw claims in its message.
                raise InvalidToken("Invalid access token") from mismatch
            if self._hooks:
                self._hooks.on_failure(reason="invalid_payload", token_type="access")  # nosec B106
            raise InvalidToken("Invalid access token") from ex

        if self._hooks:
            self._hooks.on_success(jti=result.jti, sub=result.sub, token_type="access")  # nosec B106

        return result

    def _build_decode_kwargs(self, secrets: TokenSecret) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "key": secrets.secret_key.get_secret_value(),
            "algorithms": self._config.allowed_algorithms,
            "options": {
                "require": self._config.required_claims,
                "verify_aud": self._config.require_aud,
                "verify_iss": self._config.require_iss,
            },
            "leeway": self._config.leeway_seconds,
        }
        if self._config.require_aud:
            kwargs["audience"] = self._config.audience
        if self._config.require_iss:
            kwargs["issuer"] = self._config.issuer
        return kwargs

    def _decode_payload(
        self,
        token: str,
        secrets: TokenSecret,
        kid: str | None = None,
    ) -> dict[str, Any]:
        try:
            try:
                return jwt.decode(token, **self._build_decode_kwargs(secrets))
            except InvalidSignatureError:
                rotated = self._rotated_secrets(secrets, kid)
                if rotated is None:
                    raise
                return jwt.decode(token, **self._build_decode_kwargs(rotated))
        except ExpiredSignatureError as ex:
            if self._hooks:
                self._hooks.on_failure(reason="expired", token_type="access")  # nosec B106
            raise InvalidToken("Access token expired") from ex
        except PyJWTError as ex:
            if self._hooks:
                self._hooks.on_failure(reason="invalid", token_type="access")  # nosec B106
            raise InvalidToken("Invalid access token") from ex

    def _rotated_secrets(
        self, used: TokenSecret, kid: str | None
    ) -> TokenSecret | None:
        """Re-resolve *kid* after a signature failure, if the key moved.

        A signature failure on a ``kid`` the resolver just served is the one
        symptom of key material replaced under an unchanged identifier: the
        cache still answers the lookup, so nothing else marks it stale, and the
        service rejects every live token until the TTL runs out.  Ask the
        resolver for current material once and retry only when it actually
        differs from what failed.

        The resolver owns the throttle (see ``JwksKeyResolver.refresh``), so a
        flood of forged signatures cannot escalate into a fetch storm.  Anything
        that cannot refresh, refuses, or returns the same key falls straight
        through to the original failure — exactly one extra decode at most.
        """
        resolver = self._key_resolver
        if resolver is None or not isinstance(resolver, RefreshableKeyResolver):
            return None

        try:
            rotated = resolver.refresh(kid)
        except _RESOLVER_ERRORS:
            return None

        if rotated is None or rotated.algorithm not in self._config.allowed_algorithms:
            return None
        if rotated.secret_key.get_secret_value() == used.secret_key.get_secret_value():
            return None  # Same material — the signature is simply invalid.

        return rotated

    def _resolve_secrets(self, token: str) -> tuple[TokenSecret, str | None]:
        """Resolve the signing key for this token, with the ``kid`` it came from.

        The ``kid`` is returned alongside the key so a later signature failure
        can re-resolve it without parsing the header a second time.  It is
        ``None`` for a statically keyed validator, which has nothing to refresh.
        """
        if self._key_resolver is None:
            if self._default_secrets is None:
                raise RuntimeError(
                    "key_resolver is None but default_secrets was not provided"
                )
            return self._default_secrets, None

        try:
            header = jwt.get_unverified_header(token)
        except PyJWTError as ex:
            raise InvalidToken("Invalid access token") from ex

        kid = header.get("kid")
        try:
            secrets = self._key_resolver.resolve(kid)
        except _RESOLVER_ERRORS as ex:
            raise InvalidToken("Invalid access token") from ex

        if secrets.algorithm not in self._config.allowed_algorithms:
            raise ValueError(
                f"Algorithm '{secrets.algorithm}' not allowed by configuration"
            )

        return secrets, kid
