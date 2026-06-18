"""HMAC signing tests for the Redis event bus (F3, 1.0.0).

Covers the signing helper and the signed publish / verify-on-consume wiring in
EventBus, EventPublisher and EventSubscriber: signed messages fire handlers;
tampered, wrong-key or (by default) unsigned messages are dropped.
"""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from auth_sdk_m8.redis_events._signing import deserialize, serialize
from auth_sdk_m8.redis_events.event_bus import EventBus
from auth_sdk_m8.redis_events.publisher import EventPublisher
from auth_sdk_m8.redis_events.subscriber import EventSubscriber
from auth_sdk_m8.schemas.user_events import UserDeletedEvent

_REDIS_URL = "redis://localhost:6379"
KEY = "Abcdef-1234_XYZ-abcdef-ghijkl-mnopqr-stuvwx"
OTHER_KEY = "Zyxwvu-9876_ABC-zyxwvu-tsrqpo-nmlkji-hgfedc"

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _make_redis_mock():
    mock_redis = MagicMock()
    mock_redis.publish = AsyncMock()
    mock_redis.aclose = AsyncMock()
    mock_pubsub = MagicMock()
    mock_pubsub.subscribe = AsyncMock()
    mock_pubsub.close = AsyncMock()
    mock_redis.pubsub.return_value = mock_pubsub
    return mock_redis, mock_pubsub


def _feed_once(mock_pubsub, data: str) -> None:
    """Configure get_message to yield one message then cancel the reader loop."""
    call_count = 0

    async def side_effect(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {"type": "message", "data": data}
        raise asyncio.CancelledError()

    mock_pubsub.get_message = AsyncMock(side_effect=side_effect)


# ── signing helper ────────────────────────────────────────────────────────────


def test_serialize_unsigned_passthrough() -> None:
    assert json.loads(serialize({"a": 1}, None)) == {"a": 1}


def test_serialize_signed_envelope_roundtrips() -> None:
    raw = serialize({"a": 1, "b": 2}, KEY)
    env = json.loads(raw)
    assert set(env) == {"payload", "sig"}
    assert deserialize(raw, KEY) == {"a": 1, "b": 2}


def test_deserialize_tampered_payload_dropped() -> None:
    env = json.loads(serialize({"a": 1}, KEY))
    env["payload"]["a"] = 999  # tamper after signing
    assert deserialize(json.dumps(env), KEY) is None


def test_deserialize_wrong_key_dropped() -> None:
    raw = serialize({"a": 1}, KEY)
    assert deserialize(raw, OTHER_KEY) is None


def test_deserialize_unsigned_dropped_by_default() -> None:
    assert deserialize(json.dumps({"a": 1}), KEY) is None


def test_deserialize_unsigned_accepted_with_flag() -> None:
    assert deserialize(json.dumps({"a": 1}), KEY, accept_unsigned=True) == {"a": 1}


def test_deserialize_no_key_passthrough() -> None:
    assert deserialize(json.dumps({"a": 1}), None) == {"a": 1}


# ── EventBus / EventPublisher publish signing ─────────────────────────────────


async def test_event_bus_signs_published_payload() -> None:
    with patch("auth_sdk_m8.redis_events.event_bus.redis.from_url") as mock_from_url:
        mock_redis, _ = _make_redis_mock()
        mock_from_url.return_value = mock_redis
        bus = EventBus(_REDIS_URL, signing_key=KEY)
        await bus.publish("user.deleted", UserDeletedEvent(user_id="u1"))

        raw = mock_redis.publish.call_args[0][1]
        env = json.loads(raw)
        assert set(env) == {"payload", "sig"}
        decoded = deserialize(raw, KEY)
        assert decoded is not None
        assert decoded["user_id"] == "u1"


async def test_event_publisher_signs_published_payload() -> None:
    with patch("auth_sdk_m8.redis_events.publisher.redis.from_url") as mock_from_url:
        mock_redis, _ = _make_redis_mock()
        mock_from_url.return_value = mock_redis
        publisher = EventPublisher(_REDIS_URL, signing_key=KEY)
        await publisher.publish("ch", {"hello": "world"})

        raw = mock_redis.publish.call_args[0][1]
        assert deserialize(raw, KEY) == {"hello": "world"}


# ── EventBus consume verification ─────────────────────────────────────────────


async def test_event_bus_fires_handler_on_valid_signature() -> None:
    with patch("auth_sdk_m8.redis_events.event_bus.redis.from_url") as mock_from_url:
        mock_redis, mock_pubsub = _make_redis_mock()
        mock_from_url.return_value = mock_redis
        payload = {"event_type": "user.deleted", "user_id": "ok", "version": "v1"}
        _feed_once(mock_pubsub, serialize(payload, KEY))

        handler = AsyncMock()
        bus = EventBus(_REDIS_URL, signing_key=KEY)
        await bus.subscribe("user.deleted", UserDeletedEvent, handler)
        assert bus.task is not None
        await bus.task

        handler.assert_called_once()
        assert handler.call_args[0][0].user_id == "ok"


async def test_event_bus_drops_tampered_message() -> None:
    with patch("auth_sdk_m8.redis_events.event_bus.redis.from_url") as mock_from_url:
        mock_redis, mock_pubsub = _make_redis_mock()
        mock_from_url.return_value = mock_redis
        env = json.loads(
            serialize(
                {"event_type": "user.deleted", "user_id": "x", "version": "v1"}, KEY
            )
        )
        env["payload"]["user_id"] = "tampered"
        _feed_once(mock_pubsub, json.dumps(env))

        handler = AsyncMock()
        bus = EventBus(_REDIS_URL, signing_key=KEY)
        await bus.subscribe("user.deleted", UserDeletedEvent, handler)
        assert bus.task is not None
        await bus.task

        handler.assert_not_called()


# ── EventSubscriber consume verification ──────────────────────────────────────


async def test_event_subscriber_fires_handler_on_valid_signature() -> None:
    with patch("auth_sdk_m8.redis_events.subscriber.redis.from_url") as mock_from_url:
        mock_redis, mock_pubsub = _make_redis_mock()
        mock_from_url.return_value = mock_redis
        _feed_once(mock_pubsub, serialize({"user_id": "ok"}, KEY))

        handler = AsyncMock()
        subscriber = EventSubscriber(_REDIS_URL, signing_key=KEY)
        await subscriber.subscribe("ch", handler)
        assert subscriber.task is not None
        await subscriber.task

        handler.assert_called_once_with({"user_id": "ok"})


async def test_event_subscriber_drops_unsigned_when_required() -> None:
    with patch("auth_sdk_m8.redis_events.subscriber.redis.from_url") as mock_from_url:
        mock_redis, mock_pubsub = _make_redis_mock()
        mock_from_url.return_value = mock_redis
        _feed_once(mock_pubsub, json.dumps({"user_id": "unsigned"}))

        handler = AsyncMock()
        subscriber = EventSubscriber(_REDIS_URL, signing_key=KEY)
        await subscriber.subscribe("ch", handler)
        assert subscriber.task is not None
        await subscriber.task

        handler.assert_not_called()


async def test_event_subscriber_accepts_unsigned_in_transitional_mode() -> None:
    with patch("auth_sdk_m8.redis_events.subscriber.redis.from_url") as mock_from_url:
        mock_redis, mock_pubsub = _make_redis_mock()
        mock_from_url.return_value = mock_redis
        _feed_once(mock_pubsub, json.dumps({"user_id": "legacy"}))

        handler = AsyncMock()
        subscriber = EventSubscriber(_REDIS_URL, signing_key=KEY, accept_unsigned=True)
        await subscriber.subscribe("ch", handler)
        assert subscriber.task is not None
        await subscriber.task

        handler.assert_called_once_with({"user_id": "legacy"})
