"""
Lightweight Redis event subscriber.

Requires the `redis` extra:  pip install "auth-sdk-m8[redis]"
"""
import asyncio
import json
import logging
from typing import Any, Awaitable, Callable, Dict

import redis.asyncio as redis

logger = logging.getLogger(__name__)


class EventSubscriber:
    """
    Subscribe to Redis Pub/Sub channels and dispatch raw dict payloads.

    For typed events with Pydantic validation, prefer ``EventBus`` instead.
    """

    def __init__(self, redis_url: str) -> None:
        self.redis: redis.Redis = redis.from_url(redis_url, decode_responses=True)
        self.pubsub = self.redis.pubsub()
        self.task: asyncio.Task | None = None

    async def subscribe(
        self,
        channel: str,
        handler: Callable[[Dict[str, Any]], Awaitable[None]],
    ) -> None:
        """
        Subscribe to *channel* and invoke *handler* for each message.

        Args:
            channel: Redis channel name.
            handler: Async callable that receives the decoded JSON payload.
        """
        await self.pubsub.subscribe(channel)

        async def _reader() -> None:
            while True:
                try:
                    message = await self.pubsub.get_message(
                        ignore_subscribe_messages=True, timeout=1.0
                    )
                    if message and message["type"] == "message":
                        await handler(json.loads(message["data"]))
                except asyncio.CancelledError:
                    break
                except Exception:
                    logger.exception(
                        "EventSubscriber: error processing message on channel %r",
                        channel,
                    )
                    await asyncio.sleep(1)

        self.task = asyncio.create_task(_reader())

    async def close(self) -> None:
        """Cancel the reader task and close all Redis connections."""
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
        await self.pubsub.close()
        await self.redis.aclose()
