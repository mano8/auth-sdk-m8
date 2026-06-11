"""Auth event-stream client (fa-auth SSE bridge).

The chosen transport for auth-state events is an authenticated Server-Sent
Events stream on fa-auth's private API — not the deprecated Redis Pub/Sub bus
(see :mod:`auth_sdk_m8.redis_events`). Consumers run an
:class:`~auth_sdk_m8.events.stream_client.AuthEventStreamClient` to receive
``session-revoked`` / ``user-deleted`` notifications as a best-effort cache
accelerator; the JTI blacklist remains the authority.

Requires the ``events`` extra:  ``pip install "auth-sdk-m8[events]"``.
"""

from auth_sdk_m8.events.stream_client import (
    AuthEventStreamClient,
    AuthStreamEvent,
    derive_stream_url,
)

__all__ = [
    "AuthEventStreamClient",
    "AuthStreamEvent",
    "derive_stream_url",
]
