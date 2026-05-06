"""
Lightweight Redis event publisher.

Requires the `redis` extra:  pip install "auth-sdk-m8[redis]"
"""

import json
import logging
from typing import Any, Dict

import redis.asyncio as redis

logger = logging.getLogger(__name__)


class EventPublisher:
    """
    Publish raw dict payloads to Redis Pub/Sub channels.

    For typed publishing, prefer ``EventBus.publish`` instead.
    """

    def __init__(self, redis_url: str) -> None:
        self.redis: redis.Redis = redis.from_url(redis_url, decode_responses=True)

    async def publish(self, channel: str, event: Dict[str, Any]) -> None:
        """
        Serialize *event* to JSON and publish it to *channel*.

        Args:
            channel: Redis channel name.
            event: Payload dict to publish.
        """
        await self.redis.publish(channel, json.dumps(event))

    async def close(self) -> None:
        """Close the underlying Redis connection."""
        await self.redis.aclose()
