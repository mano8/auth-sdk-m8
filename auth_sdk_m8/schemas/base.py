"""Shared enums and response schemas for m8 microservices."""

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class AuthProviderType(str, Enum):
    """Authentication providers supported by auth_user_service."""

    PASSWORD = "password"  # nosec B105  # noqa: S105
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
        """Return True if current_role has at least the privilege of role_limit.

        Delegates to :func:`auth_sdk_m8.authorization.has_minimum_role`, the
        canonical hierarchy check, so this method and the new stable public
        API can never drift apart. Imported locally to avoid a circular
        import (``authorization`` imports :class:`RoleType` from this module).
        """
        from auth_sdk_m8.authorization import has_minimum_role

        return has_minimum_role(current_role, role_limit)


class ApiKeyAccessMode(str, Enum):
    """Immutable operation-category cap chosen when an API key is issued.

    An access mode is **not** a role: the key never stores a role of its own,
    and the owner's current role remains the authority ceiling. The mode only
    narrows what an already-authorized owner may do through this key.

    - ``READ_ONLY`` permits eligible read operations only.
    - ``READ_WRITE`` permits eligible reads, and writes only when the current
      owner is itself authorized to write.

    The mode is fixed at issuance — changing it requires issuing a replacement
    key — so promoting an owner never widens an existing key.
    """

    READ_ONLY = "read_only"
    READ_WRITE = "read_write"


class Period(str, Enum):
    """Time-period options used for rate limits and recurring intervals."""

    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"
    MONTH = "month"


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
