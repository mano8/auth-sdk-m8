"""Lightweight Redis event subscriber.

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
from typing import Any, Awaitable, Callable, Dict, Optional

import redis.asyncio as redis

from auth_sdk_m8.redis_events._signing import deserialize

logger = logging.getLogger(__name__)

_DEPRECATION_MSG = (
    "{cls} is deprecated and will be removed in auth-sdk-m8 2.0.0. "
    "Use AuthEventStreamClient (auth_sdk_m8.events) — the fa-auth SSE bridge "
    "is the chosen transport for auth-state events."
)


class EventSubscriber:
    """Subscribe to Redis Pub/Sub channels and dispatch raw dict payloads.

    For typed events with Pydantic validation, prefer ``EventBus`` instead.
    Secure-by-default: pass *signing_key* (from ``EVENT_SIGNING_KEY``) to verify
    each message's HMAC signature before invoking the handler; forged or (unless
    *accept_unsigned*) unsigned messages are dropped.
    """

    def __init__(
        self,
        redis_url: str,
        *,
        signing_key: Optional[str] = None,
        accept_unsigned: bool = False,
    ) -> None:
        warnings.warn(
            _DEPRECATION_MSG.format(cls="EventSubscriber"),
            DeprecationWarning,
            stacklevel=2,
        )
        self.redis: redis.Redis = redis.from_url(redis_url, decode_responses=True)
        self.pubsub = self.redis.pubsub()
        self.task: asyncio.Task | None = None
        self._signing_key = signing_key
        self._accept_unsigned = accept_unsigned

    async def subscribe(
        self,
        channel: str,
        handler: Callable[[Dict[str, Any]], Awaitable[None]],
    ) -> None:
        """Subscribe to *channel* and invoke *handler* for each message.

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
                        payload = deserialize(
                            message["data"],
                            self._signing_key,
                            accept_unsigned=self._accept_unsigned,
                        )
                        if payload is None:
                            continue
                        await handler(payload)
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
