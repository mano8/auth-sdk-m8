"""Base event-envelope schema shared by auth event-stream payloads."""

from pydantic import BaseModel


class EventBase(BaseModel):
    """Base class for all typed event payloads."""

    event_type: str
    version: str = "v1"
