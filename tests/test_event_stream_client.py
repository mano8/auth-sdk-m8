"""Tests for auth_sdk_m8.events — AuthEventStreamClient and helpers.

Covers:
- derive_stream_url derivation from JTI-status URL and bare base URLs.
- AuthStreamEvent dataclass fields.
- AuthEventStreamClient reconnect / resume / gap / sig-verify paths.
"""

import asyncio
import builtins
import json
import logging
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from prometheus_client import CollectorRegistry

import auth_sdk_m8.events.stream_client as _stream_mod
import auth_sdk_m8.observability.metrics as _metrics_mod
from auth_sdk_m8.events import AuthEventStreamClient, AuthStreamEvent, derive_stream_url
from auth_sdk_m8.events._signing import serialize
from auth_sdk_m8.events.stream_client import _get_metrics
from auth_sdk_m8.security import static_internal_auth

KEY = "Abcdef-1234_XYZ-abcdef-ghijkl-mnopqr-stuvwx"
_STREAM_URL = "http://auth:8000/private/v1/events/stream"
_SECRET = "my-internal-secret"
_CLIENT_ID = "test-consumer"

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


# ── AuthEventStreamClient helpers ─────────────────────────────────────────────


def _make_client(
    on_event=None,
    on_gap=None,
    signing_key=KEY,
) -> AuthEventStreamClient:
    return AuthEventStreamClient(
        stream_url=_STREAM_URL,
        auth_provider=static_internal_auth(_SECRET, client_id=_CLIENT_ID),
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


# ── auth provider (Phase 9.1 event-stream) ────────────────────────────────────


def _make_provider(headers: dict | None = None) -> AsyncMock:
    """Build an AsyncMock InternalAuthProvider returning *headers*."""
    provider = AsyncMock()
    provider.headers.return_value = dict(
        headers or {"X-Internal-Client": "svc", "Authorization": "Bearer tok"}
    )
    provider.invalidate.return_value = True
    return provider


def test_requires_auth_provider() -> None:
    """A missing auth_provider → ValueError (the legacy secret path is retired)."""
    with pytest.raises(ValueError, match="auth_provider is required"):
        AuthEventStreamClient(
            stream_url=_STREAM_URL,
            signing_key=KEY,
            on_event=AsyncMock(),
            on_gap=AsyncMock(),
        )


async def test_auth_provider_headers_used_on_connect() -> None:
    """The provider supplies the per-connection headers (e.g. Bearer token)."""
    provider = _make_provider({"Authorization": "Bearer tok"})
    client = AuthEventStreamClient(
        stream_url=_STREAM_URL,
        signing_key=KEY,
        on_event=AsyncMock(),
        on_gap=AsyncMock(),
        auth_provider=provider,
    )

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

        await client._connect_and_read()

    provider.headers.assert_awaited_once()
    assert mock_cls.call_args[1]["headers"]["Authorization"] == "Bearer tok"


def _unauthorized_resp(status_code: int) -> MagicMock:
    """A mock response whose raise_for_status raises HTTPStatusError(status)."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.raise_for_status = MagicMock(
        side_effect=httpx.HTTPStatusError(
            "error", request=httpx.Request("GET", _STREAM_URL), response=resp
        )
    )
    return resp


async def test_401_invalidates_provider_then_reraises() -> None:
    """A 401 on connect invalidates the provider so the next attempt re-mints."""
    provider = _make_provider()
    client = AuthEventStreamClient(
        stream_url=_STREAM_URL,
        signing_key=KEY,
        on_event=AsyncMock(),
        on_gap=AsyncMock(),
        auth_provider=provider,
    )

    with patch("auth_sdk_m8.events.stream_client.httpx.AsyncClient") as mock_cls:
        mock_instance = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_cm.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_cm

        stream_cm = MagicMock()
        stream_cm.__aenter__ = AsyncMock(return_value=_unauthorized_resp(401))
        stream_cm.__aexit__ = AsyncMock(return_value=False)
        mock_instance.stream.return_value = stream_cm

        with pytest.raises(httpx.HTTPStatusError):
            await client._connect_and_read()

    provider.invalidate.assert_awaited_once()


async def test_non_401_status_does_not_invalidate() -> None:
    """A non-401 HTTP error re-raises without invalidating the provider."""
    provider = _make_provider()
    client = AuthEventStreamClient(
        stream_url=_STREAM_URL,
        signing_key=KEY,
        on_event=AsyncMock(),
        on_gap=AsyncMock(),
        auth_provider=provider,
    )

    with patch("auth_sdk_m8.events.stream_client.httpx.AsyncClient") as mock_cls:
        mock_instance = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_cm.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_cm

        stream_cm = MagicMock()
        stream_cm.__aenter__ = AsyncMock(return_value=_unauthorized_resp(503))
        stream_cm.__aexit__ = AsyncMock(return_value=False)
        mock_instance.stream.return_value = stream_cm

        with pytest.raises(httpx.HTTPStatusError):
            await client._connect_and_read()

    provider.invalidate.assert_not_awaited()


async def test_stop_closes_auth_provider() -> None:
    """stop() closes the owned auth provider even when never started."""
    provider = _make_provider()
    client = AuthEventStreamClient(
        stream_url=_STREAM_URL,
        signing_key=KEY,
        on_event=AsyncMock(),
        on_gap=AsyncMock(),
        auth_provider=provider,
    )
    await client.stop()
    provider.close.assert_awaited_once()


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


# ── observability: revocation-cache metrics (Phase 7.x.2) ─────────────────────


@pytest.fixture
def metrics_registry(monkeypatch):
    """Fresh metrics registry with the auth group enabled; reset afterwards."""
    fresh = CollectorRegistry(auto_describe=False)
    monkeypatch.setattr(_metrics_mod, "REGISTRY", fresh)
    monkeypatch.setattr(_metrics_mod, "_m", None)
    _metrics_mod.setup(enabled=True, groups_str="auth", api_prefix="")
    yield fresh
    monkeypatch.setattr(_metrics_mod, "_m", None)


def _sv(registry: CollectorRegistry, name: str, labels: dict | None = None) -> float:
    return registry.get_sample_value(name, labels or {}) or 0.0


async def test_metrics_signed_event_counts_delivered(metrics_registry) -> None:
    """A verified (signed) event is dispatched and counted as delivered."""
    on_event = AsyncMock()
    client = _make_client(on_event=on_event)
    payload = {"event_type": "session.revoked", "user_id": "u1", "jti": "j1"}
    lines = ["event: session-revoked", f"data: {serialize(payload, KEY)}", ""]

    await client._read_sse(_sse_response(lines))

    on_event.assert_called_once()
    assert (
        _sv(
            metrics_registry,
            "auth_event_stream_events_total",
            {"event_type": "session-revoked", "result": "delivered"},
        )
        == 1.0
    )


async def test_metrics_forged_event_counts_sig_fail_no_delivery(
    metrics_registry,
) -> None:
    """A forged (wrong-key) event is dropped — counted as sig fail, not delivered."""
    on_event = AsyncMock()
    client = _make_client(on_event=on_event)
    other_key = "Zyxwvu-9876_ABC-zyxwvu-tsrqpo-nmlkji-hgfedc"
    forged = serialize({"event_type": "session.revoked", "user_id": "x"}, other_key)
    lines = ["event: session-revoked", f"data: {forged}", ""]

    await client._read_sse(_sse_response(lines))

    on_event.assert_not_called()
    assert (
        _sv(
            metrics_registry,
            "auth_event_stream_events_total",
            {"event_type": "session-revoked", "result": "dropped_sig_fail"},
        )
        == 1.0
    )
    assert (
        _sv(
            metrics_registry,
            "auth_event_stream_events_total",
            {"event_type": "session-revoked", "result": "delivered"},
        )
        == 0.0
    )


async def test_metrics_malformed_event_counts_dropped(metrics_registry) -> None:
    """A frame whose data fails to deserialize is counted as dropped_malformed."""
    client = _make_client()
    lines = ["event: user-deleted", "data: {not-valid-json", ""]

    await client._read_sse(_sse_response(lines))

    assert (
        _sv(
            metrics_registry,
            "auth_event_stream_events_total",
            {"event_type": "user-deleted", "result": "dropped_malformed"},
        )
        == 1.0
    )


async def test_metrics_gap_increments_gap_total(metrics_registry) -> None:
    """A gap signal increments the cache-flush counter and calls on_gap."""
    on_gap = AsyncMock()
    client = _make_client(on_gap=on_gap)
    client._last_event_id = "1-5"

    await client._read_sse(_sse_response(["event: gap", "data: unresumable", ""]))

    on_gap.assert_called_once()
    assert _sv(metrics_registry, "auth_event_stream_gap_total") == 1.0


async def test_metrics_connected_gauge_set_then_cleared(metrics_registry) -> None:
    """The connection gauge reads 1 while streaming and 0 once it ends."""
    client = _make_client()
    seen: list[float] = []

    resp = MagicMock()
    resp.raise_for_status = MagicMock()

    async def _iter():
        seen.append(_sv(metrics_registry, "auth_event_stream_connected"))
        if False:  # noqa: SIM210
            yield  # pragma: no cover

    resp.aiter_lines = _iter

    with patch("auth_sdk_m8.events.stream_client.httpx.AsyncClient") as mock_cls:
        mock_instance = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_instance)
        mock_cm.__aexit__ = AsyncMock(return_value=False)
        mock_cls.return_value = mock_cm

        stream_cm = MagicMock()
        stream_cm.__aenter__ = AsyncMock(return_value=resp)
        stream_cm.__aexit__ = AsyncMock(return_value=False)
        mock_instance.stream.return_value = stream_cm

        await client._connect_and_read()

    assert seen == [1.0]
    assert _sv(metrics_registry, "auth_event_stream_connected") == 0.0


async def test_metrics_reconnect_counter_increments(metrics_registry) -> None:
    """Each disconnect that triggers a reconnect bumps the reconnect counter."""
    call_count = 0

    async def _fail_then_cancel():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise ConnectionError("transient")
        raise asyncio.CancelledError()

    client = _make_client()
    with patch.object(client, "_connect_and_read", side_effect=_fail_then_cancel):
        with patch(
            "auth_sdk_m8.events.stream_client.asyncio.sleep", new_callable=AsyncMock
        ):
            await client._run()

    assert _sv(metrics_registry, "auth_event_stream_reconnects_total") == 1.0


def test_get_metrics_none_without_observability(monkeypatch) -> None:
    """_get_metrics returns None when the observability extra is not installed."""
    real_import = builtins.__import__

    def _fake_import(name, *args, **kwargs):
        if name == "auth_sdk_m8.observability.metrics":
            raise ImportError("observability extra not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    assert _get_metrics() is None


def test_get_metrics_returns_container_when_enabled(metrics_registry) -> None:
    """_get_metrics returns the live container when observability is set up."""
    assert _get_metrics() is _metrics_mod.get()
    assert _stream_mod._get_metrics() is not None


# ── no-secret-logging acceptance (Phase 7.x.2) ────────────────────────────────


async def test_secrets_never_logged_across_paths(metrics_registry, caplog) -> None:
    """Neither the private-API secret nor the signing key appears in any log."""
    caplog.set_level(logging.DEBUG, logger="auth_sdk_m8.events.stream_client")
    client = _make_client(on_event=AsyncMock(), on_gap=AsyncMock())

    # delivered, malformed, sig-fail, and gap paths all log.
    delivered = serialize({"event_type": "session.revoked", "user_id": "u"}, KEY)
    forged = serialize(
        {"event_type": "session.revoked"}, "Zyxwvu-9876_ABC-zyxwvu-tsrqpo-nmlkji-hg"
    )
    lines = [
        "event: session-revoked",
        f"data: {delivered}",
        "",
        "event: user-deleted",
        "data: {bad",
        "",
        "event: session-revoked",
        f"data: {forged}",
        "",
        "event: gap",
        "data: unresumable",
        "",
    ]
    await client._read_sse(_sse_response(lines))

    # a disconnect log path too: one transient error, then cancel to exit.
    errors = [ConnectionError("x"), asyncio.CancelledError()]

    async def _fail_then_cancel():
        raise errors.pop(0)

    with patch.object(client, "_connect_and_read", side_effect=_fail_then_cancel):
        with patch(
            "auth_sdk_m8.events.stream_client.asyncio.sleep", new_callable=AsyncMock
        ):
            await client._run()

    blob = "\n".join(r.getMessage() for r in caplog.records)
    assert _SECRET not in blob
    assert KEY not in blob
