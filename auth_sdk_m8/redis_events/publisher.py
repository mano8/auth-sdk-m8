"""Lightweight Redis event publisher.

.. deprecated::
    The Redis Pub/Sub transport is not the chosen transport for auth-state
    events in the m8 fleet. Use :class:`auth_sdk_m8.events.AuthEventStreamClient`
    (the fa-auth SSE bridge) instead. These classes will be removed in 2.0.0.
    ``_signing.py`` is exempt — the SSE bridge reuses it.

Requires the `redis` extra:  pip install "auth-sdk-m8[redis]"
"""

import logging
import warnings
from typing import Any, Dict, Optional

import redis.asyncio as redis

from auth_sdk_m8.redis_events._signing import serialize

logger = logging.getLogger(__name__)

_DEPRECATION_MSG = (
    "{cls} is deprecated and will be removed in auth-sdk-m8 2.0.0. "
    "Use AuthEventStreamClient (auth_sdk_m8.events) — the fa-auth SSE bridge "
    "is the chosen transport for auth-state events."
)


class EventPublisher:
    """Publish raw dict payloads to Redis Pub/Sub channels.

    For typed publishing, prefer ``EventBus.publish`` instead.  Pass
    *signing_key* (from ``EVENT_SIGNING_KEY``) to HMAC-sign published payloads;
    subscribers configured with the same key reject unsigned/forged messages.
    """

    def __init__(self, redis_url: str, *, signing_key: Optional[str] = None) -> None:
        warnings.warn(
            _DEPRECATION_MSG.format(cls="EventPublisher"),
            DeprecationWarning,
            stacklevel=2,
        )
        self.redis: redis.Redis = redis.from_url(redis_url, decode_responses=True)
        self._signing_key = signing_key

    async def publish(self, channel: str, event: Dict[str, Any]) -> None:
        """Serialize *event* (signing it when a key is set) and publish it.

        Args:
            channel: Redis channel name.
            event: Payload dict to publish.
        """
        await self.redis.publish(channel, serialize(event, self._signing_key))

    async def close(self) -> None:
        """Close the underlying Redis connection."""
        await self.redis.aclose()
