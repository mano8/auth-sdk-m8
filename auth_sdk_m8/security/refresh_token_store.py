"""Async store protocol for refresh token rotation tracking."""

from typing import Protocol


class RefreshTokenStore(Protocol):
    """Backend-agnostic store for refresh-token rotation and revocation.

    Implement this against Redis, a relational DB, or any other backend.
    The SDK ships no concrete implementation — callers provide their own
    so there is no forced infrastructure dependency.

    Usage with ``RefreshTokenPolicy``::

        class RedisRefreshStore:
            def __init__(self, redis: Redis) -> None:
                self._r = redis

            async def is_valid(self, jti: str) -> bool:
                return bool(await self._r.exists(f"rt:{jti}"))

            async def rotate(
                self, old_jti: str, new_jti: str, ttl_seconds: int
            ) -> None:
                pipe = self._r.pipeline()
                pipe.delete(f"rt:{old_jti}")
                pipe.setex(f"rt:{new_jti}", ttl_seconds, "1")
                await pipe.execute()

            async def revoke(self, jti: str) -> None:
                await self._r.delete(f"rt:{jti}")
    """

    async def is_valid(self, jti: str) -> bool:
        """Return True if *jti* is a known, active refresh token."""

    async def rotate(self, old_jti: str, new_jti: str, ttl_seconds: int) -> None:
        """Invalidate *old_jti* and register *new_jti* as active.

        Args:
            old_jti: The JTI being consumed.
            new_jti: The JTI for the replacement token.
            ttl_seconds: How long *new_jti* remains valid.
        """

    async def revoke(self, jti: str) -> None:
        """Mark *jti* as revoked (call on explicit logout or reuse detection)."""
