"""Redis-backed JTI blacklist check for revoked access tokens."""

from redis import Redis


class AccessTokenBlacklist:
    """Read-only JTI blacklist backed by Redis.

    Consumer services use this to verify that an access token has not been
    revoked by the auth service.  The auth service writes entries via
    ``RedisSessionManager.blacklist_jti()`` using the same key prefix.

    Args:
        client: An open Redis connection with decode_responses=True.
    """

    PREFIX = "jwt:blacklist:"

    def __init__(self, client: Redis) -> None:
        self._client = client

    def is_revoked(self, jti: str) -> bool:
        """Return True when *jti* is present in the blacklist."""
        return bool(self._client.exists(self.PREFIX + jti))
