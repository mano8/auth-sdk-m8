"""Pure JWT validation helpers."""

from typing import Any

import jwt
from jwt import ExpiredSignatureError, PyJWTError
from pydantic import ValidationError

from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.auth import TokenSecret, TokenUserData
from auth_sdk_m8.security.key_resolver import KeyResolver
from auth_sdk_m8.security.validation import TokenValidationConfig


class TokenValidator:
    """
    Pure access-token validator with no I/O or storage dependencies.

    This validator is intentionally synchronous. Stateful or network-backed
    checks belong in a separate policy layer.
    """

    def __init__(
        self,
        secrets: TokenSecret | None,
        config: TokenValidationConfig,
        key_resolver: KeyResolver | None = None,
    ) -> None:
        self._default_secrets = secrets
        self._config = config
        self._key_resolver = key_resolver

        if self._default_secrets is None and self._key_resolver is None:
            raise ValueError(
                "Either secrets or key_resolver must be provided"
            )

        if (
            self._default_secrets is not None
            and self._default_secrets.algorithm
            not in self._config.allowed_algorithms
        ):
            raise ValueError(
                "Algorithm "
                f"'{self._default_secrets.algorithm}' not allowed by configuration"
            )

    def validate_access_token(self, token: str) -> TokenUserData:
        """Decode and validate an access token."""
        secrets = self._resolve_secrets(token)
        decode_kwargs: dict[str, Any] = {
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
            decode_kwargs["audience"] = self._config.audience

        if self._config.require_iss:
            decode_kwargs["issuer"] = self._config.issuer

        try:
            payload = jwt.decode(token, **decode_kwargs)
        except ExpiredSignatureError as ex:
            raise InvalidToken("Access token expired") from ex
        except PyJWTError as ex:
            raise InvalidToken("Invalid access token") from ex

        if payload.get("type") != "access":
            raise InvalidToken("Not an access token")

        try:
            return TokenUserData(**payload)
        except ValidationError as ex:
            raise InvalidToken("Invalid access token") from ex

    def _resolve_secrets(self, token: str) -> TokenSecret:
        """Resolve the signing key for this token."""
        if self._key_resolver is None:
            assert self._default_secrets is not None
            return self._default_secrets

        try:
            header = jwt.get_unverified_header(token)
        except PyJWTError as ex:
            raise InvalidToken("Invalid access token") from ex

        try:
            secrets = self._key_resolver.resolve(header.get("kid"))
        except (LookupError, TypeError, ValueError) as ex:
            raise InvalidToken("Invalid access token") from ex

        if secrets.algorithm not in self._config.allowed_algorithms:
            raise ValueError(
                f"Algorithm '{secrets.algorithm}' not allowed by configuration"
            )

        return secrets
