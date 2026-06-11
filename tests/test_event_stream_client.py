"""Tests for auth_sdk_m8.events — AuthEventStreamClient and helpers.

Covers:
- derive_stream_url derivation from JTI-status URL and bare base URLs.
- AuthStreamEvent dataclass fields.
- AuthEventStreamClient reconnect / resume / gap / sig-verify paths.
- Deprecation warning from EventBus / EventPublisher / EventSubscriber.
"""

import asyncio
import json
import warnings
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from auth_sdk_m8.events import AuthEventStreamClient, AuthStreamEvent, derive_stream_url
from auth_sdk_m8.redis_events._signing import serialize
from auth_sdk_m8.redis_events.event_bus import EventBus
from auth_sdk_m8.redis_events.publisher import EventPublisher
from auth_sdk_m8.redis_events.subscriber import EventSubscriber

_REDIS_URL = "redis://localhost:6379"
KEY = "Abcdef-1234_XYZ-abcdef-ghijkl-mnopqr-stuvwx"
_STREAM_URL = "http://auth:8000/private/v1/events/stream"
_SECRET = "my-internal-secret"

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


# ── derive_stream_url ─────────────────────────────────────────────────────────


def test_derive_stream_url_from_jti_status() -> None:
    url = derive_stream_url("http://auth:8000/private/v1/jti-status")
    assert url == "http://auth:8000/private/v1/events/stream"


def test_derive_stream_url_from_jti_status_trailing_slash() -> None:
    url = derive_stream_url("http://auth:8000/private/v1/jti-status/")
    assert url == "http://auth:8000/private/v1/events/stream"


def test_derive_stream_url_from_bare_base() -> None:
    url = derive_stream_url("http://auth:8000/private/v1")
    assert url == "http://auth:8000/private/v1/events/stream"


def test_derive_stream_url_from_bare_base_trailing_slash() -> None:
    url = derive_stream_url("http://auth:8000/private/v1/")
    assert url == "http://auth:8000/private/v1/events/stream"


# ── AuthStreamEvent ───────────────────────────────────────────────────────────


def test_auth_stream_event_fields() -> None:
    ev = AuthStreamEvent(
        event_type="session-revoked", payload={"jti": "abc"}, event_id="1-2"
    )
    assert ev.event_type == "session-revoked"
    assert ev.payload == {"jti": "abc"}
    assert ev.event_id == "1-2"


def test_auth_stream_event_no_id() -> None:
    ev = AuthStreamEvent(event_type="user-deleted", payload={}, event_id=None)
    assert ev.event_id is None


# ── DeprecationWarning from Redis classes ─────────────────────────────────────


def test_event_bus_emits_deprecation_warning() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with patch("auth_sdk_m8.redis_events.event_bus.redis.from_url"):
            EventBus(_REDIS_URL)
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)
    assert any("EventBus" in str(w.message) for w in caught)


def test_event_publisher_emits_deprecation_warning() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with patch("auth_sdk_m8.redis_events.publisher.redis.from_url"):
            EventPublisher(_REDIS_URL)
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)
    assert any("EventPublisher" in str(w.message) for w in caught)


def test_event_subscriber_emits_deprecation_warning() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        with patch("auth_sdk_m8.redis_events.subscriber.redis.from_url"):
            EventSubscriber(_REDIS_URL)
    assert any(issubclass(w.category, DeprecationWarning) for w in caught)
    assert any("EventSubscriber" in str(w.message) for w in caught)


# ── AuthEventStreamClient helpers ─────────────────────────────────────────────


def _make_client(
    on_event=None,
    on_gap=None,
    signing_key=KEY,
) -> AuthEventStreamClient:
    return AuthEventStreamClient(
        stream_url=_STREAM_URL,
        private_api_secret=_SECRET,
        signing_key=signing_key,
        on_event=on_event or AsyncMock(),
        on_gap=on_gap or AsyncMock(),
    )


def _sse_response(lines: list[str]) -> MagicMock:
    """Build a mock httpx streaming response that yields *lines* then closes."""
    resp = MagicMock()
    resp.raise_for_status = MagicMock()

    async def _iter_lines():
        for line in lines:
            yield line

    resp.aiter_lines = _iter_lines
    return resp


# ── start / stop lifecycle ────────────────────────────────────────────────────


async def test_start_creates_task() -> None:
    client = _make_client()
    with patch.object(client, "_run", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = None
        client.start()
        assert client._task is not None
        await client.stop()


async def test_stop_cancels_task() -> None:
    client = _make_client()
    ran = asyncio.Event()

    async def _slow():
        ran.set()
        await asyncio.sleep(100)

    with patch.object(client, "_run", side_effect=_slow):
        client.start()
        await ran.wait()
        await client.stop()
        assert client._task is None


async def test_stop_noop_when_not_started() -> None:
    client = _make_client()
    await client.stop()  # should not raise


# ── verified event delivery ───────────────────────────────────────────────────


async def test_verified_event_dispatched_to_callback() -> None:
    on_event = AsyncMock()
    client = _make_client(on_event=on_event)

    payload = {"event_type": "session.revoked", "user_id": "u1", "jti": "j1"}
    signed_data = serialize(payload, KEY)
    lines = [
        "id: 1-1",
        "event: session-revoked",
        f"data: {signed_data}",
        "",
    ]
    resp = _sse_response(lines)
    await client._read_sse(resp)

    on_event.assert_called_once()
    ev: AuthStreamEvent = on_event.call_args[0][0]
    assert ev.event_type == "session-revoked"
    assert ev.payload["user_id"] == "u1"
    assert ev.event_id == "1-1"
    assert client._last_event_id == "1-1"


async def test_invalid_sig_dropped_no_callback() -> None:
    on_event = AsyncMock()
    client = _make_client(on_event=on_event)

    other_key = "Zyxwvu-9876_ABC-zyxwvu-tsrqpo-nmlkji-hgfedc"
    signed_data = serialize({"event_type": "user.deleted", "user_id": "x"}, other_key)
    lines = ["event: user-deleted", f"data: {signed_data}", ""]
    await client._read_sse(_sse_response(lines))

    on_event.assert_not_called()


async def test_gap_event_clears_last_id_and_calls_on_gap() -> None:
    on_gap = AsyncMock()
    client = _make_client(on_gap=on_gap)
    client._last_event_id = "1-5"

    lines = ["event: gap", "data: unresumable", ""]
    await client._read_sse(_sse_response(lines))

    on_gap.assert_called_once()
    assert client._last_event_id is None


async def test_heartbeat_comment_ignored() -> None:
    on_event = AsyncMock()
    client = _make_client(on_event=on_event)
    lines = [": ping", ""]
    await client._read_sse(_sse_response(lines))
    on_event.assert_not_called()


async def test_multiline_data_joined() -> None:
    on_event = AsyncMock()
    client = _make_client(on_event=on_event)

    payload = {"a": 1}
    full = serialize(payload, KEY)
    # Split the JSON at a boundary to simulate multi-line data (rare but valid SSE)
    mid = len(full) // 2
    lines = [
        "event: session-revoked",
        f"data: {full[:mid]}",
        f"data: {full[mid:]}",
        "",
    ]
    # The joined data won't parse as valid JSON/envelope since we split mid-token,
    # so the sig check will fail — that's expected. We just verify it doesn't crash.
    await client._read_sse(_sse_response(lines))
    # on_event may or may not be called depending on whether joined data is valid;
    # the key assertion is that no exception propagated.


async def test_on_event_exception_does_not_propagate() -> None:
    async def _raising(ev):
        raise RuntimeError("boom")

    client = _make_client(on_event=_raising)
    payload = {"event_type": "session.revoked", "user_id": "u"}
    lines = ["event: session-revoked", f"data: {serialize(payload, KEY)}", ""]
    await client._read_sse(_sse_response(lines))  # must not raise


async def test_on_gap_exception_does_not_propagate() -> None:
    async def _raising():
        raise RuntimeError("boom gap")

    client = _make_client(on_gap=_raising)
    lines = ["event: gap", "data: unresumable", ""]
    await client._read_sse(_sse_response(lines))  # must not raise


# ── no-signing-key path ───────────────────────────────────────────────────────


async def test_no_signing_key_accepts_any_payload() -> None:
    on_event = AsyncMock()
    client = _make_client(on_event=on_event, signing_key=None)

    raw = json.dumps({"event_type": "user.deleted", "user_id": "u2"})
    lines = ["event: user-deleted", f"data: {raw}", ""]
    await client._read_sse(_sse_response(lines))

    on_event.assert_called_once()
    ev: AuthStreamEvent = on_event.call_args[0][0]
    assert ev.payload["user_id"] == "u2"


# ── Last-Event-ID resume ──────────────────────────────────────────────────────


async def test_last_event_id_sent_on_reconnect() -> None:
    """The stored Last-Event-ID is included in the reconnect request headers."""
    client = _make_client()
    client._last_event_id = "1-42"

    with patch("auth_sdk_m8.events.stream_client.httpx.AsyncClient") as mock_cls:
        mock_instance = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_cm.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_cm

        stream_cm = MagicMock()
        stream_cm.__aenter__ = AsyncMock(return_value=_fake_resp())
        stream_cm.__aexit__ = AsyncMock(return_value=False)
        mock_instance.stream.return_value = stream_cm

        try:
            await client._connect_and_read()
        except Exception:
            pass

        call_kwargs = mock_cls.call_args[1]
        assert call_kwargs["headers"]["Last-Event-ID"] == "1-42"


def _fake_resp() -> MagicMock:
    """Build a mock response whose aiter_lines yields nothing (empty stream)."""
    resp = MagicMock()
    resp.raise_for_status = MagicMock()

    async def _iter():
        # async generator with no items — simulates an empty stream
        if False:  # noqa: SIM210
            yield  # pragma: no cover

    resp.aiter_lines = _iter
    return resp


# ── _run reconnect loop ───────────────────────────────────────────────────────


async def test_run_reconnects_after_error() -> None:
    """_run loops on transient errors; CancelledError exits cleanly."""
    call_count = 0

    async def _connect_once():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise ConnectionError("transient")
        # Second call: simulate cancellation — _run returns cleanly.
        raise asyncio.CancelledError()

    client = _make_client()
    with patch.object(client, "_connect_and_read", side_effect=_connect_once):
        with patch(
            "auth_sdk_m8.events.stream_client.asyncio.sleep", new_callable=AsyncMock
        ):
            await client._run()  # returns after catching CancelledError
    assert call_count == 2


async def test_run_cancelled_exits_cleanly() -> None:
    """CancelledError from _connect_and_read terminates _run without re-scheduling."""
    client = _make_client()

    async def _cancel():
        raise asyncio.CancelledError()

    with patch.object(client, "_connect_and_read", side_effect=_cancel):
        await client._run()  # should return cleanly


async def test_run_resets_backoff_after_success() -> None:
    """A successful connection resets backoff before the next iteration."""
    call_count = 0

    async def _succeed_then_cancel():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return  # success — triggers backoff reset on line 151
        raise asyncio.CancelledError()

    client = _make_client()
    with patch.object(client, "_connect_and_read", side_effect=_succeed_then_cancel):
        with patch(
            "auth_sdk_m8.events.stream_client.asyncio.sleep", new_callable=AsyncMock
        ):
            await client._run()
    assert call_count == 2
