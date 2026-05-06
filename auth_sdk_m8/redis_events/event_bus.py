"""
Typed Redis Pub/Sub event bus.

Requires the `redis` extra:  pip install "auth-sdk-m8[redis]"
"""

import asyncio
import json
import logging
from typing import Awaitable, Callable, Type

import redis.asyncio as redis

from auth_sdk_m8.schemas.redis_events import EventBase

logger = logging.getLogger(__name__)


class EventBus:
    """
    Publish and subscribe to strongly-typed Redis Pub/Sub events.

    Usage::

        bus = EventBus("redis://localhost:6379")

        async def handle(event: UserDeletedEvent) -> None:
            ...

        await bus.subscribe("user.deleted", UserDeletedEvent, handle)
        # keep running …
        await bus.close()
    """

    def __init__(self, redis_url: str) -> None:
        self.redis = redis.from_url(redis_url, decode_responses=True)
        self.pubsub = self.redis.pubsub()
        self.task: asyncio.Task | None = None

    async def publish(self, channel: str, event: EventBase) -> None:
        """Serialize *event* and publish it to *channel*."""
        await self.redis.publish(channel, event.model_dump_json())

    async def subscribe(
        self,
        channel: str,
        event_schema: Type[EventBase],
        handler: Callable[[EventBase], Awaitable[None]],
    ) -> None:
        """
        Subscribe to *channel* and dispatch validated events to *handler*.

        Args:
            channel: Redis channel name.
            event_schema: Pydantic model class used to validate each message.
            handler: Async callable that receives the validated event.
        """
        await self.pubsub.subscribe(channel)

        async def _reader() -> None:
            while True:
                try:
                    message = await self.pubsub.get_message(
                        ignore_subscribe_messages=True, timeout=1.0
                    )
                    if message and message["type"] == "message":
                        payload = json.loads(message["data"])
                        await handler(event_schema(**payload))
                except asyncio.CancelledError:
                    break
                except Exception:
                    logger.exception(
                        "EventBus: error processing message on channel %r",
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
