"""Stateful refresh-token policy with rotation and reuse detection."""

import uuid
from datetime import datetime, timezone

import jwt
from jwt import ExpiredSignatureError, PyJWTError

from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.auth import TokenSecret
from auth_sdk_m8.security.hooks import ValidationHooks
from auth_sdk_m8.security.refresh_token_store import RefreshTokenStore

_ALLOWED_ALGORITHMS: frozenset[str] = frozenset({"HS256", "RS256", "ES256"})


def _decode_refresh(
    token: str,
    secrets: TokenSecret,
) -> tuple[uuid.UUID, str]:
    """Decode and validate a refresh token, returning (user_id, jti).

    Kept private — callers should use ``RefreshTokenPolicy``.
    """
    if secrets.algorithm not in _ALLOWED_ALGORITHMS:
        raise InvalidToken("Unsupported signing algorithm for refresh token")

    try:
        payload = jwt.decode(
            token,
            secrets.secret_key.get_secret_value(),
            algorithms=[secrets.algorithm],
            options={"require": ["exp", "sub", "jti", "type"]},
        )
    except ExpiredSignatureError as ex:
        raise InvalidToken("Refresh token expired") from ex
    except PyJWTError as ex:
        raise InvalidToken("Invalid refresh token") from ex

    if payload.get("type") != "refresh":
        raise InvalidToken("Not a refresh token")

    exp = payload.get("exp")
    if exp is None or exp < datetime.now(timezone.utc).timestamp():
        raise InvalidToken("Refresh token expired")

    try:
        user_id = uuid.UUID(payload["sub"])
    except (ValueError, AttributeError) as ex:
        raise InvalidToken("Invalid refresh token") from ex

    jti = payload.get("jti")
    if not isinstance(jti, str) or not jti:
        raise InvalidToken("Invalid refresh token")

    return user_id, jti


class RefreshTokenPolicy:
    """Enforce refresh-token rotation and reuse detection.

    Wraps JWT refresh-token decoding with an optional store-backed rotation
    layer.  When a *store* is provided:

    * A reused (already-consumed) JTI immediately raises ``InvalidToken``.
      Callers should treat reuse as a compromise signal and consider
      revoking all sessions for the user.
    * A valid JTI is atomically swapped for *new_jti* via
      ``RefreshTokenStore.rotate``.

    Without a *store* the policy degrades to pure JWT validation — correct
    for stateless deployments where token expiry is the only revocation
    mechanism.

    Args:
        secrets: Signing key and algorithm used to verify refresh tokens.
        store: Optional rotation/revocation backend.
        hooks: Optional observability callbacks (logging, metrics).

    Example::

        policy = RefreshTokenPolicy(
            secrets=TokenSecret(
                secret_key=SecretStr(settings.REFRESH_SECRET_KEY),
                algorithm="HS256",
            ),
            store=RedisRefreshStore(redis),
        )

        user_id, old_jti = await policy.validate_and_rotate(
            incoming_refresh_token,
            new_jti=str(uuid.uuid4()),
        )
        # Issue new access + refresh tokens bound to user_id / new_jti.
    """

    def __init__(
        self,
        secrets: TokenSecret,
        store: RefreshTokenStore | None = None,
        hooks: ValidationHooks | None = None,
    ) -> None:
        self._secrets = secrets
        self._store = store
        self._hooks = hooks

    async def validate_and_rotate(
        self,
        token: str,
        new_jti: str,
        ttl_seconds: int = 86_400,
    ) -> tuple[uuid.UUID, str]:
        """Validate *token*, detect reuse, then rotate its JTI.

        Args:
            token: Encoded refresh token string.
            new_jti: The JTI to assign the replacement refresh token.
            ttl_seconds: Lifetime for *new_jti* in the store (default: 24 h).

        Returns:
            ``(user_id, old_jti)`` — use *user_id* to issue a new access
            token and *old_jti* for audit logging / manual cleanup.

        Raises:
            InvalidToken: Token invalid, expired, reused, or revoked.
        """
        try:
            user_id, old_jti = _decode_refresh(token, self._secrets)
        except InvalidToken:
            if self._hooks:
                self._hooks.on_failure(reason="invalid", token_type="refresh")  # nosec B106 - event label, not a password
            raise

        if self._store is not None:
            if not await self._store.is_valid(old_jti):
                if self._hooks:
                    self._hooks.on_failure(reason="reused", token_type="refresh")  # nosec B106
                raise InvalidToken("Refresh token already used or revoked")
            await self._store.rotate(old_jti, new_jti, ttl_seconds)

        if self._hooks:
            self._hooks.on_success(jti=new_jti, sub=str(user_id), token_type="refresh")  # nosec B106

        return user_id, old_jti

    async def revoke(self, jti: str) -> None:
        """Revoke a refresh token by JTI.

        Call this on explicit logout.  No-op when no store is configured.
        """
        if self._store is not None:
            await self._store.revoke(jti)
