"""
dm_model's helpers
"""
import uuid
from typing import Any

from sqlalchemy import types
from sqlalchemy.engine.interfaces import Dialect


# pylint: disable=too-many-ancestors, disable=abstract-method
class UUIDChar(types.TypeDecorator):
    """
    Store UUID values as CHAR(36).

    Converts:
    - uuid.UUID -> str on bind
    - str -> uuid.UUID on result

    Compatible with PostgreSQL, MySQL, and SQLite.
    """

    impl = types.CHAR(36)
    cache_ok = True

    @property
    def python_type(self) -> type[uuid.UUID]:
        """Return the underlying Python type."""
        return uuid.UUID

    def process_bind_param(
        self,
        value: Any,
        dialect: Dialect,
    ) -> str | None:
        """Convert UUID to string before storing."""
        if value is None:
            return None

        if isinstance(value, uuid.UUID):
            return str(value)

        return str(uuid.UUID(value))

    def process_result_value(
        self,
        value: Any,
        dialect: Dialect,
    ) -> uuid.UUID | None:
        """Convert database value back to UUID."""
        if value is None:
            return None

        return uuid.UUID(str(value))

    def process_literal_param(
        self,
        value: Any,
        dialect: Dialect,
    ) -> str | None:
        """Render UUID literals safely."""
        if value is None:
            return None

        if isinstance(value, uuid.UUID):
            return str(value)

        return str(uuid.UUID(value))
