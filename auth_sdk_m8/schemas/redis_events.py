"""Base event schema for the Redis Pub/Sub event bus."""

from pydantic import BaseModel


class EventBase(BaseModel):
    """Base class for all typed event payloads."""

    event_type: str
    version: str = "v1"
