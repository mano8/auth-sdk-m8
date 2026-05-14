"""Optional stateful policy layer for token validation."""

from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.auth import TokenUserData
from auth_sdk_m8.security.hooks import ValidationHooks
from auth_sdk_m8.security.session_store import SessionStore
from auth_sdk_m8.security.token_validator import TokenValidator


class TokenPolicy:
    """Apply optional store-backed policy checks after JWT validation.

    Args:
        validator: Cryptographic validator to run first.
        store: Optional revocation backend.  When present,
            ``is_revoked`` is called after every successful JWT decode.
        hooks: Optional observability callbacks.  Receives a
            ``"revoked"`` failure event when the store rejects a token.
    """

    def __init__(
        self,
        validator: TokenValidator,
        store: SessionStore | None = None,
        hooks: ValidationHooks | None = None,
    ) -> None:
        self.validator = validator
        self.store = store
        self._hooks = hooks

    async def validate(self, token: str) -> TokenUserData:
        """Validate an access token and enforce optional revocation checks."""
        payload = self.validator.validate_access_token(token)

        if self.store and await self.store.is_revoked(payload.jti):
            if self._hooks:
                self._hooks.on_failure(reason="revoked", token_type="access")  # nosec B106 - event label, not a password
            raise InvalidToken("Token revoked")

        return payload
