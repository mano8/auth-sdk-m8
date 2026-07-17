"""User- and session-related event schemas for the auth event stream.

These typed payloads ride the fa-auth SSE bridge. They share the
:class:`EventBase` envelope and are signed/verified with the ``_signing``
helpers regardless of transport.
"""

from typing import Optional

from pydantic import Field

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

    **v2 (additive, 3.5.2):** ``auth_generation`` and ``event_id`` are new,
    optional fields layered onto the same shape. ``user_id`` and ``jti`` keep
    their exact v1 names and semantics, so an old consumer parses a v2 event
    safely by ignoring the fields it does not know about. A v1 event —
    ``version="v1"`` (the :class:`EventBase` default), no ``auth_generation``
    — carries neither new field; consumers treat that as conservative
    (user-wide) eviction rather than a precise generation comparison.

    Attributes:
        user_id: Owner of the revoked session(s).
        jti: The specific access-token JTI that was revoked. ``None`` means
            *all* of the user's sessions were revoked at once.
        auth_generation: The owner's generation backing this revocation.
            ``None`` on a v1 event or when the generation could not be
            captured; consumers tag/evict cache entries by this value per the
            watermark rule (3.5.2), never by the transport's SSE stream id.
        event_id: Durable, deterministic dedup key — the outbox row's
            ``(user_id, auth_generation, effect_type, target_digest)`` key (or
            a UUID stored on that row). Distinct from the SSE transport id
            (``epoch-seq``), which resets on issuer restart and is never used
            for durable deduplication. ``None`` on a v1 event.
    """

    event_type: str = "session.revoked"
    user_id: str
    jti: Optional[str] = None
    auth_generation: Optional[int] = Field(default=None, ge=1)
    event_id: Optional[str] = Field(default=None, min_length=1)
