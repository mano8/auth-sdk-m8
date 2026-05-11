"""
dm_model's helpers - UUID TypeDecorator
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import types
from sqlalchemy.engine.interfaces import Dialect


class UUIDChar(types.TypeDecorator):
    """
    Store UUID values as CHAR(36).

    Normalization rules:
    - Always store as string
    - Accept uuid.UUID or valid UUID string
    - Always return uuid.UUID on read
    """

    impl = types.CHAR(36)
    cache_ok = True

    @property
    def python_type(self) -> type[uuid.UUID]:
        """Python type exposed to SQLAlchemy."""
        return uuid.UUID

    def _normalize(self, value: Any) -> uuid.UUID | None:
        """
        Normalize input into uuid.UUID.

        Accepts:
        - uuid.UUID
        - valid UUID string
        """
        if value is None:
            return None

        if isinstance(value, uuid.UUID):
            return value

        return uuid.UUID(str(value))

    def process_bind_param(
        self,
        value: Any,
        dialect: Dialect,
    ) -> str | None:
        """
        Convert Python value -> DB value (string).
        """
        uuid_value = self._normalize(value)
        return None if uuid_value is None else str(uuid_value)

    def process_result_value(
        self,
        value: Any,
        dialect: Dialect,
    ) -> uuid.UUID | None:
        """
        Convert DB value -> Python UUID.
        """
        if value is None:
            return None

        return uuid.UUID(str(value))

    def process_literal_param(
        self,
        value: Any,
        dialect: Dialect,
    ) -> str | None:
        """
        Convert literal SQL param safely.
        """
        uuid_value = self._normalize(value)
        return None if uuid_value is None else str(uuid_value)
