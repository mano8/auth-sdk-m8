"""AuthEventStreamClient — httpx-based SSE client for the fa-auth bridge.

Connects to ``GET /private/v1/events/stream`` on the fa-auth private API,
authenticates via ``X-Internal-Token``, and dispatches verified events to
caller-supplied callbacks. Never raises into the host application: all
exceptions are logged and the client reconnects with jittered backoff.

Requires the ``events`` extra:  ``pip install "auth-sdk-m8[events]"``.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional

import httpx

from auth_sdk_m8.events._signing import deserialize

logger = logging.getLogger(__name__)


def _get_metrics():
    """Return the observability metrics container, or ``None`` when unavailable.

    Observability is an optional extra (``auth-sdk-m8[observability]``); the
    event-stream client must keep working without it, so the import is guarded
    and metric emission is best-effort. Never raises.
    """
    try:
        from auth_sdk_m8.observability.metrics import get
    except ImportError:  # observability extra not installed
        return None
    return get()


# SSE stream endpoint suffix, appended to the private-API base URL.
# INTROSPECTION_URL example: http://fa-auth:8000/private/v1/jti-status
# → strip /jti-status → http://fa-auth:8000/private/v1 → + /events/stream
_STREAM_SUFFIX = "/events/stream"
_JTI_STATUS_SUFFIX = "/jti-status"

# Reconnect back-off: base 1 s, cap 60 s, ±25 % jitter.
_BACKOFF_BASE = 1.0
_BACKOFF_CAP = 60.0
_BACKOFF_JITTER = 0.25


def derive_stream_url(introspection_url: str) -> str:
    """Derive the SSE stream URL from the JTI-status introspection URL.

    The introspection URL points at ``/private/v1/jti-status``.  The stream
    lives at ``/private/v1/events/stream`` on the same host/prefix.

    Args:
        introspection_url: Value of ``INTROSPECTION_URL`` (may end with
            ``/jti-status`` or already be a bare private-API base URL).

    Returns:
        Absolute URL of the SSE stream endpoint.
    """
    url = introspection_url.rstrip("/")
    if url.endswith(_JTI_STATUS_SUFFIX):
        url = url[: -len(_JTI_STATUS_SUFFIX)]
    return url.rstrip("/") + _STREAM_SUFFIX


@dataclass(frozen=True)
class AuthStreamEvent:
    """A verified, parsed event received from the fa-auth bridge.

    Attributes:
        event_type: SSE ``event:`` field value (e.g. ``session-revoked``).
        payload: Verified inner payload dict (signature already checked).
        event_id: SSE ``id:`` value, used as ``Last-Event-ID`` on reconnect.
    """

    event_type: str
    payload: dict
    event_id: Optional[str]


class AuthEventStreamClient:
    """Authenticated SSE client for the fa-auth event-stream bridge.

    Connects to ``GET /private/v1/events/stream`` using the existing
    ``PRIVATE_API_SECRET`` (``X-Internal-Token`` header). Incoming ``data``
    frames are verified via HMAC-SHA256 (same ``EVENT_SIGNING_KEY`` used for
    the Redis transport). Reconnects automatically with jittered exponential
    back-off; passes ``Last-Event-ID`` so the server can replay the gap.

    Caller responsibilities:

    - Provide ``on_event`` — called for every verified event.
    - Provide ``on_gap`` — called when the server signals an unresumable gap
      (epoch change or buffer eviction); callers **must** flush all locally
      cached validation state.
    - Start the client in an ``asyncio`` event loop (e.g. in a FastAPI
      ``lifespan`` context) via :meth:`start` / :meth:`stop`.

    The client *never* raises into the caller from background tasks. Errors
    are logged at WARNING level and trigger a reconnect.

    Args:
        stream_url: Full URL of the SSE stream endpoint.
        private_api_secret: Raw ``PRIVATE_API_SECRET`` string.
        signing_key: ``EVENT_SIGNING_KEY`` raw string for HMAC verification.
            Pass ``None`` only when signing is disabled on the server too.
        on_event: Async callback invoked with each verified
            :class:`AuthStreamEvent`.
        on_gap: Async callback invoked when the stream is unresumable; caller
            must flush caches and return promptly.
        connect_timeout: Seconds to wait for the initial connection.
        read_timeout: Seconds to wait between SSE frames (heartbeat interval
            should be well below this).
    """

    def __init__(
        self,
        *,
        stream_url: str,
        private_api_secret: str,
        signing_key: Optional[str],
        on_event: Callable[[AuthStreamEvent], Awaitable[None]],
        on_gap: Callable[[], Awaitable[None]],
        connect_timeout: float = 5.0,
        read_timeout: float = 60.0,
    ) -> None:
        self._url = stream_url
        self._secret = private_api_secret
        self._signing_key = signing_key
        self._on_event = on_event
        self._on_gap = on_gap
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._task: asyncio.Task | None = None
        self._last_event_id: Optional[str] = None

    def start(self) -> None:
        """Start the background reader task."""
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        """Cancel the background reader task and wait for it to finish."""
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None

    # ── observability (best-effort; no secrets are ever logged or labelled) ────

    def _set_connected(self, connected: bool) -> None:
        """Record the SSE connection state (1 connected / 0 disconnected)."""
        m = _get_metrics()
        if m is None or m.event_stream_connected is None:
            return
        m.event_stream_connected.set(1 if connected else 0)

    def _note_reconnect(self) -> None:
        """Count a disconnect that triggers a reconnect."""
        m = _get_metrics()
        if m is None or m.event_stream_reconnects_total is None:
            return
        m.event_stream_reconnects_total.inc()

    def _note_gap(self) -> None:
        """Count an unresumable gap that forces a local cache flush."""
        m = _get_metrics()
        if m is None or m.event_stream_gap_total is None:
            return
        m.event_stream_gap_total.inc()

    def _note_event(self, event_type: str, result: str) -> None:
        """Count a received frame by outcome (delivered / dropped_*)."""
        m = _get_metrics()
        if m is None or m.event_stream_events_total is None:
            return
        m.event_stream_events_total.labels(event_type=event_type, result=result).inc()

    # ── internal ──────────────────────────────────────────────────────────────

    async def _run(self) -> None:
        """Main reconnect loop — runs until cancelled."""
        backoff = _BACKOFF_BASE
        while True:
            try:
                await self._connect_and_read()
                backoff = _BACKOFF_BASE
            except asyncio.CancelledError:
                return
            except Exception as exc:
                logger.warning(
                    "auth.event_stream disconnected error=%s reconnect_in=%.1fs",
                    exc,
                    backoff,
                )
            self._note_reconnect()
            jitter = (
                backoff * _BACKOFF_JITTER * (secrets.randbelow(2001) / 1000.0 - 1.0)
            )
            await asyncio.sleep(max(0.1, backoff + jitter))
            backoff = min(backoff * 2, _BACKOFF_CAP)

    async def _connect_and_read(self) -> None:
        """Open a single SSE connection and read until it closes."""
        headers: dict[str, str] = {"X-Internal-Token": self._secret}
        if self._last_event_id is not None:
            headers["Last-Event-ID"] = self._last_event_id

        async with httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(
                connect=self._connect_timeout,
                read=self._read_timeout,
                write=5.0,
                pool=5.0,
            ),
        ) as client:
            async with client.stream("GET", self._url) as response:
                response.raise_for_status()
                self._set_connected(True)
                logger.info("auth.event_stream connected url=%s", self._url)
                try:
                    await self._read_sse(response)
                finally:
                    self._set_connected(False)

    async def _read_sse(self, response: httpx.Response) -> None:
        """Parse SSE lines and dispatch events."""
        event_type: Optional[str] = None
        data_lines: list[str] = []
        event_id: Optional[str] = None

        async for line in response.aiter_lines():
            if line.startswith(":"):
                # Heartbeat / comment — reset nothing, just keep the conn alive.
                continue

            if not line:
                # Empty line → dispatch accumulated event.
                if data_lines:
                    await self._dispatch(
                        event_type or "message",
                        "\n".join(data_lines),
                        event_id,
                    )
                event_type = None
                data_lines = []
                event_id = None
                continue

            if line.startswith("id:"):
                event_id = line[3:].strip()
            elif line.startswith("event:"):
                event_type = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].strip())

    async def _dispatch(
        self,
        event_type: str,
        raw_data: str,
        event_id: Optional[str],
    ) -> None:
        """Verify signature and invoke the appropriate callback."""
        if event_type == "gap":
            # Server signals unresumable gap — caller must flush caches.
            self._last_event_id = None
            self._note_gap()
            logger.info(
                "auth.event_stream gap signalled — flushing local revocation cache"
            )
            try:
                await self._on_gap()
            except Exception:
                logger.exception("auth.event_stream on_gap callback raised")
            return

        try:
            payload = deserialize(raw_data, self._signing_key)
        except Exception:
            self._note_event(event_type, "dropped_malformed")
            logger.warning(
                "auth.event_stream dropping event=%s reason=malformed_data",
                event_type,
            )
            return
        if payload is None:
            self._note_event(event_type, "dropped_sig_fail")
            logger.warning(
                "auth.event_stream dropping event=%s reason=sig_verify_failed",
                event_type,
            )
            return

        if event_id is not None:
            self._last_event_id = event_id

        event = AuthStreamEvent(
            event_type=event_type,
            payload=payload,
            event_id=event_id,
        )
        self._note_event(event_type, "delivered")
        try:
            await self._on_event(event)
        except Exception:
            logger.exception(
                "auth.event_stream on_event callback raised event_type=%s",
                event_type,
            )
