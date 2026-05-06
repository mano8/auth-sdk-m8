"""Optional async protocols for stateful token validation."""

from typing import Protocol


class SessionStore(Protocol):
    """Optional async store used for revocation checks."""

    async def is_revoked(self, jti: str) -> bool:
        """Return True when the JWT ID has been revoked."""
