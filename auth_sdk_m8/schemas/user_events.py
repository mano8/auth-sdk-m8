"""User-related event schemas for the Redis event bus."""

from auth_sdk_m8.schemas.redis_events import EventBase


class UserDeletedEvent(EventBase):
    """
    Fired by auth_user_service when a user account is deleted.

    Consuming services should use this event to clean up any local
    data associated with the deleted user.
    """

    event_type: str = "user.deleted"
    user_id: str
