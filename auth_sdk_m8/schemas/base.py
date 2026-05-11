"""Shared enums and response schemas for m8 microservices."""

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class AuthProviderType(str, Enum):
    """Authentication providers supported by auth_user_service."""

    PASSWORD = "password"
    GOOGLE = "google"


class RoleType(str, Enum):
    """User roles ordered from highest to lowest privilege."""

    SUPERADMIN = "superadmin"
    ADMIN = "admin"
    WRITER = "writer"
    READER = "reader"
    USER = "user"

    @staticmethod
    def get_ordered_roles() -> list[str]:
        """Return roles in descending privilege order."""
        return ["superadmin", "admin", "writer", "reader", "user"]

    @staticmethod
    def is_valid_role_auth(current_role: "RoleType", role_limit: "RoleType") -> bool:
        """Return True if current_role has at least the privilege of role_limit."""
        ordered = RoleType.get_ordered_roles()
        try:
            return ordered.index(current_role.value) <= ordered.index(role_limit.value)
        except ValueError:
            return False


class Period(str, Enum):
    """Time-period options used for rate limits and recurring intervals."""

    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"


# ── Response schemas ──────────────────────────────────────────────────────────


class ResponseError(BaseModel):
    """Single field-level error detail."""

    table: Optional[str] = None
    field_name: Optional[str] = None
    error: Optional[str] = None


class ResponseModelBase(BaseModel):
    """Generic success/data response wrapper."""

    success: bool
    data: Optional[Any] = None


class ResponseMessage(BaseModel):
    """Simple success + message response."""

    success: bool
    msg: str


class ResponseErrorBase(BaseModel):
    """Structured error response returned on exceptions."""

    success: bool = False
    msg: Optional[str] = None
    from_error: Optional[str] = None
    errors: list[ResponseError] = Field(default_factory=list)
    status_code: Optional[int] = None
