"""Lightweight Redis event publisher.

Requires the `redis` extra:  pip install "auth-sdk-m8[redis]"
"""

import logging
from typing import Any, Dict, Optional

import redis.asyncio as redis

from auth_sdk_m8.redis_events._signing import serialize

logger = logging.getLogger(__name__)


class EventPublisher:
    """Publish raw dict payloads to Redis Pub/Sub channels.

    For typed publishing, prefer ``EventBus.publish`` instead.  Pass
    *signing_key* (from ``EVENT_SIGNING_KEY``) to HMAC-sign published payloads;
    subscribers configured with the same key reject unsigned/forged messages.
    """

    def __init__(self, redis_url: str, *, signing_key: Optional[str] = None) -> None:
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
