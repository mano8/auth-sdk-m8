"""Key resolution interfaces for token validation."""

from typing import Protocol

from auth_sdk_m8.schemas.auth import TokenSecret


class KeyResolver(Protocol):
    """Resolve a signing key for a token based on its optional ``kid`` header."""

    def resolve(self, kid: str | None) -> TokenSecret:
        """Return the key material and algorithm for the requested key id."""
