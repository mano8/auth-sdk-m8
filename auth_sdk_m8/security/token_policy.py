"""Optional stateful policy layer for token validation."""

from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.auth import TokenUserData
from auth_sdk_m8.security.session_store import SessionStore
from auth_sdk_m8.security.token_validator import TokenValidator


class TokenPolicy:
    """Apply optional store-backed policy checks after JWT validation."""

    def __init__(
        self,
        validator: TokenValidator,
        store: SessionStore | None = None,
    ) -> None:
        self.validator = validator
        self.store = store

    async def validate(self, token: str) -> TokenUserData:
        """Validate an access token and enforce optional revocation checks."""
        payload = self.validator.validate_access_token(token)

        if self.store and await self.store.is_revoked(payload.jti):
            raise InvalidToken("Token revoked")

        return payload
