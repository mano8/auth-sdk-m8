"""Typed Redis Pub/Sub event bus.

.. deprecated::
    The Redis Pub/Sub transport is not the chosen transport for auth-state
    events in the m8 fleet. Use :class:`auth_sdk_m8.events.AuthEventStreamClient`
    (the fa-auth SSE bridge) instead. These classes will be removed in 2.0.0.
    ``_signing.py`` is exempt — the SSE bridge reuses it.

Requires the `redis` extra:  pip install "auth-sdk-m8[redis]"
"""

import asyncio
import logging
import warnings
from typing import Awaitable, Callable, Optional, Type

import redis.asyncio as redis

from auth_sdk_m8.redis_events._signing import deserialize, serialize
from auth_sdk_m8.schemas.redis_events import EventBase

logger = logging.getLogger(__name__)

_DEPRECATION_MSG = (
    "{cls} is deprecated and will be removed in auth-sdk-m8 2.0.0. "
    "Use AuthEventStreamClient (auth_sdk_m8.events) — the fa-auth SSE bridge "
    "is the chosen transport for auth-state events."
)


class EventBus:
    """Publish and subscribe to strongly-typed Redis Pub/Sub events.

    Secure-by-default: pass *signing_key* (from ``EVENT_SIGNING_KEY``) to
    HMAC-sign published payloads and reject unsigned/forged messages on
    consume.  Publishers and subscribers on a channel must share the same key.

    Usage::

        bus = EventBus("redis://localhost:6379", signing_key="…")

        async def handle(event: UserDeletedEvent) -> None:
            ...

        await bus.subscribe("user.deleted", UserDeletedEvent, handle)
        # keep running …
        await bus.close()
    """

    def __init__(
        self,
        redis_url: str,
        *,
        signing_key: Optional[str] = None,
        accept_unsigned: bool = False,
    ) -> None:
        warnings.warn(
            _DEPRECATION_MSG.format(cls="EventBus"),
            DeprecationWarning,
            stacklevel=2,
        )
        self.redis = redis.from_url(redis_url, decode_responses=True)
        self.pubsub = self.redis.pubsub()
        self.task: asyncio.Task | None = None
        self._signing_key = signing_key
        self._accept_unsigned = accept_unsigned

    async def publish(self, channel: str, event: EventBase) -> None:
        """Serialize *event* (signing it when a key is set) and publish it."""
        raw = serialize(event.model_dump(mode="json"), self._signing_key)
        await self.redis.publish(channel, raw)

    async def subscribe(
        self,
        channel: str,
        event_schema: Type[EventBase],
        handler: Callable[[EventBase], Awaitable[None]],
    ) -> None:
        """Subscribe to *channel* and dispatch validated events to *handler*.

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
                        payload = deserialize(
                            message["data"],
                            self._signing_key,
                            accept_unsigned=self._accept_unsigned,
                        )
                        if payload is None:
                            continue
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
