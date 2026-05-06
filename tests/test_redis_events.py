"""Tests for auth_sdk_m8.redis_events (EventBus, EventPublisher, EventSubscriber)."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from auth_sdk_m8.redis_events.event_bus import EventBus
from auth_sdk_m8.redis_events.publisher import EventPublisher
from auth_sdk_m8.redis_events.subscriber import EventSubscriber
from auth_sdk_m8.schemas.user_events import UserDeletedEvent

_REDIS_URL = "redis://localhost:6379"
pytestmark = pytest.mark.asyncio


# ── helpers ───────────────────────────────────────────────────────────────────


def _make_redis_mock():
    mock_redis = MagicMock()
    mock_redis.publish = AsyncMock()
    mock_redis.aclose = AsyncMock()
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = AsyncMock()
    mock_pubsub.close = AsyncMock()
    mock_redis.pubsub.return_value = mock_pubsub
    return mock_redis, mock_pubsub


# ── EventPublisher ────────────────────────────────────────────────────────────


async def test_event_publisher_publish() -> None:
    with patch("auth_sdk_m8.redis_events.publisher.redis.from_url") as mock_from_url:
        mock_redis, _ = _make_redis_mock()
        mock_from_url.return_value = mock_redis

        publisher = EventPublisher(_REDIS_URL)
        await publisher.publish("my.channel", {"key": "value"})

        mock_redis.publish.assert_called_once_with(
            "my.channel", json.dumps({"key": "value"})
        )


async def test_event_publisher_close() -> None:
    with patch("auth_sdk_m8.redis_events.publisher.redis.from_url") as mock_from_url:
        mock_redis, _ = _make_redis_mock()
        mock_from_url.return_value = mock_redis

        publisher = EventPublisher(_REDIS_URL)
        await publisher.close()

        mock_redis.aclose.assert_called_once()


# ── EventBus ──────────────────────────────────────────────────────────────────


async def test_event_bus_publish() -> None:
    with patch("auth_sdk_m8.redis_events.event_bus.redis.from_url") as mock_from_url:
        mock_redis, mock_pubsub = _make_redis_mock()
        mock_from_url.return_value = mock_redis

        bus = EventBus(_REDIS_URL)
        event = UserDeletedEvent(user_id="user-123")
        await bus.publish("user.deleted", event)

        mock_redis.publish.assert_called_once()
        call_args = mock_redis.publish.call_args
        assert call_args[0][0] == "user.deleted"
        payload = json.loads(call_args[0][1])
        assert payload["user_id"] == "user-123"


async def test_event_bus_subscribe_processes_message() -> None:
    with patch("auth_sdk_m8.redis_events.event_bus.redis.from_url") as mock_from_url:
        mock_redis, mock_pubsub = _make_redis_mock()
        mock_from_url.return_value = mock_redis

        message_data = json.dumps(
            {"event_type": "user.deleted", "user_id": "abc", "version": "v1"}
        )
        call_count = 0

        async def get_message_side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"type": "message", "data": message_data}
            raise asyncio.CancelledError()

        mock_pubsub.get_message = AsyncMock(side_effect=get_message_side_effect)

        handler = AsyncMock()
        bus = EventBus(_REDIS_URL)
        await bus.subscribe("user.deleted", UserDeletedEvent, handler)
        await bus.task  # task finishes naturally when CancelledError is caught

        handler.assert_called_once()
        received_event = handler.call_args[0][0]
        assert isinstance(received_event, UserDeletedEvent)
        assert received_event.user_id == "abc"


async def test_event_bus_subscribe_no_message() -> None:
    with patch("auth_sdk_m8.redis_events.event_bus.redis.from_url") as mock_from_url:
        mock_redis, mock_pubsub = _make_redis_mock()
        mock_from_url.return_value = mock_redis

        call_count = 0

        async def get_message_side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return None  # no message
            raise asyncio.CancelledError()

        mock_pubsub.get_message = AsyncMock(side_effect=get_message_side_effect)
        handler = AsyncMock()
        bus = EventBus(_REDIS_URL)
        await bus.subscribe("ch", UserDeletedEvent, handler)
        await bus.task

        handler.assert_not_called()


async def test_event_bus_subscribe_wrong_message_type() -> None:
    with patch("auth_sdk_m8.redis_events.event_bus.redis.from_url") as mock_from_url:
        mock_redis, mock_pubsub = _make_redis_mock()
        mock_from_url.return_value = mock_redis

        call_count = 0

        async def get_message_side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"type": "subscribe", "data": "1"}
            raise asyncio.CancelledError()

        mock_pubsub.get_message = AsyncMock(side_effect=get_message_side_effect)
        handler = AsyncMock()
        bus = EventBus(_REDIS_URL)
        await bus.subscribe("ch", UserDeletedEvent, handler)
        await bus.task

        handler.assert_not_called()


async def test_event_bus_subscribe_exception_handling() -> None:
    with patch("auth_sdk_m8.redis_events.event_bus.redis.from_url") as mock_from_url:
        mock_redis, mock_pubsub = _make_redis_mock()
        mock_from_url.return_value = mock_redis

        sleep_started = asyncio.Event()
        _real_sleep = asyncio.sleep

        async def mock_sleep(secs: float) -> None:
            sleep_started.set()
            await _real_sleep(999)

        call_count = 0

        async def get_message_side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            raise RuntimeError("redis error")

        mock_pubsub.get_message = AsyncMock(side_effect=get_message_side_effect)

        handler = AsyncMock()
        bus = EventBus(_REDIS_URL)

        with patch("auth_sdk_m8.redis_events.event_bus.asyncio.sleep", mock_sleep):
            await bus.subscribe("ch", UserDeletedEvent, handler)
            await sleep_started.wait()
            # task is blocked in asyncio.sleep(999); cancel it from outside
            bus.task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await bus.task

        mock_pubsub.close = AsyncMock()
        mock_redis.aclose = AsyncMock()


async def test_event_bus_close_no_task() -> None:
    with patch("auth_sdk_m8.redis_events.event_bus.redis.from_url") as mock_from_url:
        mock_redis, mock_pubsub = _make_redis_mock()
        mock_from_url.return_value = mock_redis

        bus = EventBus(_REDIS_URL)
        assert bus.task is None
        await bus.close()

        mock_pubsub.close.assert_called_once()
        mock_redis.aclose.assert_called_once()


async def test_event_bus_close_cancels_task() -> None:
    with patch("auth_sdk_m8.redis_events.event_bus.redis.from_url") as mock_from_url:
        mock_redis, mock_pubsub = _make_redis_mock()
        mock_from_url.return_value = mock_redis

        # get_message returns None forever — task loops but yields control
        mock_pubsub.get_message = AsyncMock(return_value=None)

        bus = EventBus(_REDIS_URL)
        handler = AsyncMock()
        await bus.subscribe("ch", UserDeletedEvent, handler)

        # close() cancels the running task
        await bus.close()

        mock_pubsub.close.assert_called_once()
        mock_redis.aclose.assert_called_once()


async def test_event_bus_close_catches_cancelled_error_from_sleep() -> None:
    """Cover the 'except CancelledError: pass' branch in close()."""
    with patch("auth_sdk_m8.redis_events.event_bus.redis.from_url") as mock_from_url:
        mock_redis, mock_pubsub = _make_redis_mock()
        mock_from_url.return_value = mock_redis

        sleep_started = asyncio.Event()
        _real_sleep = asyncio.sleep

        async def mock_sleep(secs: float) -> None:
            sleep_started.set()
            await _real_sleep(999)  # blocks until cancelled

        async def always_raises(**kwargs):
            raise RuntimeError("persistent redis failure")

        mock_pubsub.get_message = AsyncMock(side_effect=always_raises)

        bus = EventBus(_REDIS_URL)
        with patch("auth_sdk_m8.redis_events.event_bus.asyncio.sleep", mock_sleep):
            await bus.subscribe("ch", UserDeletedEvent, AsyncMock())
            await sleep_started.wait()
            # Task is inside mock_sleep → asyncio.sleep(999).
            # close() will cancel it; the CancelledError propagates OUT of
            # _reader()'s except-Exception block → task dies with CancelledError.
            await bus.close()

        mock_pubsub.close.assert_called_once()
        mock_redis.aclose.assert_called_once()


# ── EventSubscriber ───────────────────────────────────────────────────────────


async def test_event_subscriber_subscribe_processes_message() -> None:
    with patch("auth_sdk_m8.redis_events.subscriber.redis.from_url") as mock_from_url:
        mock_redis, mock_pubsub = _make_redis_mock()
        mock_from_url.return_value = mock_redis

        message_data = json.dumps({"event_type": "user.deleted", "user_id": "xyz"})
        call_count = 0

        async def get_message_side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return {"type": "message", "data": message_data}
            raise asyncio.CancelledError()

        mock_pubsub.get_message = AsyncMock(side_effect=get_message_side_effect)

        handler = AsyncMock()
        subscriber = EventSubscriber(_REDIS_URL)
        await subscriber.subscribe("user.deleted", handler)
        await subscriber.task

        handler.assert_called_once()
        assert handler.call_args[0][0] == {
            "event_type": "user.deleted",
            "user_id": "xyz",
        }


async def test_event_subscriber_subscribe_no_message() -> None:
    with patch("auth_sdk_m8.redis_events.subscriber.redis.from_url") as mock_from_url:
        mock_redis, mock_pubsub = _make_redis_mock()
        mock_from_url.return_value = mock_redis

        call_count = 0

        async def get_message_side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return None
            raise asyncio.CancelledError()

        mock_pubsub.get_message = AsyncMock(side_effect=get_message_side_effect)
        handler = AsyncMock()
        subscriber = EventSubscriber(_REDIS_URL)
        await subscriber.subscribe("ch", handler)
        await subscriber.task

        handler.assert_not_called()


async def test_event_subscriber_exception_handling() -> None:
    with patch("auth_sdk_m8.redis_events.subscriber.redis.from_url") as mock_from_url:
        mock_redis, mock_pubsub = _make_redis_mock()
        mock_from_url.return_value = mock_redis

        sleep_started = asyncio.Event()
        _real_sleep = asyncio.sleep

        async def mock_sleep(secs: float) -> None:
            sleep_started.set()
            await _real_sleep(999)

        async def always_raises(**kwargs):
            raise RuntimeError("subscriber error")

        mock_pubsub.get_message = AsyncMock(side_effect=always_raises)

        subscriber = EventSubscriber(_REDIS_URL)
        with patch("auth_sdk_m8.redis_events.subscriber.asyncio.sleep", mock_sleep):
            await subscriber.subscribe("ch", AsyncMock())
            await sleep_started.wait()
            subscriber.task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await subscriber.task


async def test_event_subscriber_close_no_task() -> None:
    with patch("auth_sdk_m8.redis_events.subscriber.redis.from_url") as mock_from_url:
        mock_redis, mock_pubsub = _make_redis_mock()
        mock_from_url.return_value = mock_redis

        subscriber = EventSubscriber(_REDIS_URL)
        assert subscriber.task is None
        await subscriber.close()

        mock_pubsub.close.assert_called_once()
        mock_redis.aclose.assert_called_once()


async def test_event_subscriber_close_cancels_task() -> None:
    with patch("auth_sdk_m8.redis_events.subscriber.redis.from_url") as mock_from_url:
        mock_redis, mock_pubsub = _make_redis_mock()
        mock_from_url.return_value = mock_redis

        mock_pubsub.get_message = AsyncMock(return_value=None)

        subscriber = EventSubscriber(_REDIS_URL)
        await subscriber.subscribe("ch", AsyncMock())
        await subscriber.close()

        mock_pubsub.close.assert_called_once()
        mock_redis.aclose.assert_called_once()


async def test_event_subscriber_close_catches_cancelled_from_sleep() -> None:
    """Cover 'except CancelledError: pass' in EventSubscriber.close()."""
    with patch("auth_sdk_m8.redis_events.subscriber.redis.from_url") as mock_from_url:
        mock_redis, mock_pubsub = _make_redis_mock()
        mock_from_url.return_value = mock_redis

        sleep_started = asyncio.Event()
        _real_sleep = asyncio.sleep

        async def mock_sleep(secs: float) -> None:
            sleep_started.set()
            await _real_sleep(999)

        async def always_raises(**kwargs):
            raise RuntimeError("persistent error")

        mock_pubsub.get_message = AsyncMock(side_effect=always_raises)

        subscriber = EventSubscriber(_REDIS_URL)
        with patch("auth_sdk_m8.redis_events.subscriber.asyncio.sleep", mock_sleep):
            await subscriber.subscribe("ch", AsyncMock())
            await sleep_started.wait()
            await subscriber.close()

        mock_pubsub.close.assert_called_once()
        mock_redis.aclose.assert_called_once()
