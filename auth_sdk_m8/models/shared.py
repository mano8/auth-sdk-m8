"""Shared SQLModel mixins and base models.

Requires the `db` extra:  pip install "auth-sdk-m8[db]"
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import text
from sqlmodel import Field, SQLModel


class TimestampMixin(SQLModel):
    """Adds ``created_at`` and ``updated_at`` UTC timestamp columns.

    Include this in any SQLModel table model::

        class MyModel(TimestampMixin, SQLModel, table=True):
            id: int | None = Field(default=None, primary_key=True)
    """

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column_kwargs={
            "nullable": False,
            "server_default": text("CURRENT_TIMESTAMP"),
        },
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        sa_column_kwargs={
            "nullable": False,
            "server_default": text("CURRENT_TIMESTAMP"),
            "onupdate": text("CURRENT_TIMESTAMP"),
        },
    )


class Message(SQLModel):
    """Generic API response message."""

    message: str = Field(description="Response message content")


class Token(SQLModel):
    """JWT access token response body."""

    access_token: str = Field(description="JWT access token string")
    token_type: str = Field(default="bearer", description="Token type")


class TokenPayload(SQLModel):
    """Minimal JWT payload."""

    sub: Optional[str] = Field(default=None, description="Subject (usually user ID)")
