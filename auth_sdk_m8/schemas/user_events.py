"""User- and session-related event schemas for the auth event stream.

These typed payloads ride the fa-auth SSE bridge. They share the
:class:`EventBase` envelope and are signed/verified with the ``_signing``
helpers regardless of transport.
"""

from typing import Optional

from auth_sdk_m8.schemas.redis_events import EventBase


class UserDeletedEvent(EventBase):
    """Fired by auth_user_service when a user account is deleted.

    Consuming services should use this event to clean up any local
    data associated with the deleted user.
    """

    event_type: str = "user.deleted"
    user_id: str


class SessionRevokedEvent(EventBase):
    """Fired by auth_user_service when a session (JTI) is revoked.

    Emitted when a single session is revoked or deleted, or when every session
    for a user is revoked at once. Consumers use it as a best-effort accelerator
    to evict locally cached token-validation state; the JTI blacklist remains
    the authority, so a missed event is still safe (just slower to converge).

    Attributes:
        user_id: Owner of the revoked session(s).
        jti: The specific access-token JTI that was revoked. ``None`` means
            *all* of the user's sessions were revoked at once.
    """

    event_type: str = "session.revoked"
    user_id: str
    jti: Optional[str] = None
