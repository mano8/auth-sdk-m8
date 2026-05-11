"""Tests for dm_model helpers."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import types
from sqlalchemy.dialects import mysql, postgresql, sqlite

from auth_sdk_m8.core.db_utils import UUIDChar


@pytest.fixture(name="uuid_type")
def fixture_uuid_type() -> UUIDChar:
    """Create UUIDChar instance."""
    return UUIDChar()


@pytest.fixture(name="sample_uuid")
def fixture_sample_uuid() -> uuid.UUID:
    """Create deterministic UUID sample."""
    return uuid.UUID("550e8400-e29b-41d4-a716-446655440000")


@pytest.mark.parametrize(
    ("dialect"),
    [
        postgresql.dialect(),
        mysql.dialect(),
        sqlite.dialect(),
    ],
)
def test_process_bind_param_with_uuid_instance(
    uuid_type: UUIDChar,
    sample_uuid: uuid.UUID,
    dialect,
) -> None:
    """Should convert UUID instance to string."""
    result = uuid_type.process_bind_param(
        sample_uuid,
        dialect,
    )

    assert result == str(sample_uuid)
    assert isinstance(result, str)


@pytest.mark.parametrize(
    ("dialect"),
    [
        postgresql.dialect(),
        mysql.dialect(),
        sqlite.dialect(),
    ],
)
def test_process_bind_param_with_uuid_string(
    uuid_type: UUIDChar,
    sample_uuid: uuid.UUID,
    dialect,
) -> None:
    """Should normalize UUID string."""
    result = uuid_type.process_bind_param(
        str(sample_uuid),
        dialect,
    )

    assert result == str(sample_uuid)
    assert isinstance(result, str)


@pytest.mark.parametrize(
    ("dialect"),
    [
        postgresql.dialect(),
        mysql.dialect(),
        sqlite.dialect(),
    ],
)
def test_process_bind_param_with_none(
    uuid_type: UUIDChar,
    dialect,
) -> None:
    """Should return None unchanged."""
    result = uuid_type.process_bind_param(
        None,
        dialect,
    )

    assert result is None


@pytest.mark.parametrize(
    ("dialect"),
    [
        postgresql.dialect(),
        mysql.dialect(),
        sqlite.dialect(),
    ],
)
def test_process_bind_param_invalid_uuid_raises(
    uuid_type: UUIDChar,
    dialect,
) -> None:
    """Should raise ValueError for invalid UUID strings."""
    with pytest.raises(ValueError):
        uuid_type.process_bind_param(
            "invalid-uuid",
            dialect,
        )


@pytest.mark.parametrize(
    ("dialect"),
    [
        postgresql.dialect(),
        mysql.dialect(),
        sqlite.dialect(),
    ],
)
def test_process_result_value_returns_uuid(
    uuid_type: UUIDChar,
    sample_uuid: uuid.UUID,
    dialect,
) -> None:
    """Should convert database string to UUID."""
    result = uuid_type.process_result_value(
        str(sample_uuid),
        dialect,
    )

    assert result == sample_uuid
    assert isinstance(result, uuid.UUID)


@pytest.mark.parametrize(
    ("dialect"),
    [
        postgresql.dialect(),
        mysql.dialect(),
        sqlite.dialect(),
    ],
)
def test_process_result_value_with_none(
    uuid_type: UUIDChar,
    dialect,
) -> None:
    """Should return None unchanged."""
    result = uuid_type.process_result_value(
        None,
        dialect,
    )

    assert result is None


@pytest.mark.parametrize(
    ("dialect"),
    [
        postgresql.dialect(),
        mysql.dialect(),
        sqlite.dialect(),
    ],
)
def test_process_result_value_invalid_uuid_raises(
    uuid_type: UUIDChar,
    dialect,
) -> None:
    """Should raise ValueError for invalid database UUID."""
    with pytest.raises(ValueError):
        uuid_type.process_result_value(
            "invalid-uuid",
            dialect,
        )


@pytest.mark.parametrize(
    ("dialect"),
    [
        postgresql.dialect(),
        mysql.dialect(),
        sqlite.dialect(),
    ],
)
def test_process_literal_param_with_uuid(
    uuid_type: UUIDChar,
    sample_uuid: uuid.UUID,
    dialect,
) -> None:
    """Should render UUID literal as string."""
    result = uuid_type.process_literal_param(
        sample_uuid,
        dialect,
    )

    assert result == str(sample_uuid)
    assert isinstance(result, str)


@pytest.mark.parametrize(
    ("dialect"),
    [
        postgresql.dialect(),
        mysql.dialect(),
        sqlite.dialect(),
    ],
)
def test_process_literal_param_with_none(
    uuid_type: UUIDChar,
    dialect,
) -> None:
    """Should return None unchanged."""
    result = uuid_type.process_literal_param(
        None,
        dialect,
    )

    assert result is None


def test_python_type_property(
    uuid_type: UUIDChar,
) -> None:
    """Should expose uuid.UUID as Python type."""
    assert uuid_type.python_type is uuid.UUID


def test_cache_ok_enabled(
    uuid_type: UUIDChar,
) -> None:
    """Should enable SQLAlchemy statement caching."""
    assert uuid_type.cache_ok is True


def test_impl_is_char_36(
    uuid_type: UUIDChar,
) -> None:
    """Should use CHAR(36) as storage backend."""
    assert isinstance(uuid_type.impl, types.CHAR)
    assert uuid_type.impl.length == 36


@pytest.mark.parametrize(
    ("value"),
    [
        "550e8400-e29b-41d4-a716-446655440000",
        "{550e8400-e29b-41d4-a716-446655440000}",
        "550E8400-E29B-41D4-A716-446655440000",
    ],
)
def test_process_bind_param_string_conversion(
    uuid_type: UUIDChar,
    value: str,
) -> None:
    """Should normalize string UUID values."""
    result = uuid_type.process_bind_param(
        value,
        postgresql.dialect(),
    )

    assert result == "550e8400-e29b-41d4-a716-446655440000"


def test_process_bind_param_string_parses_uuid(
    uuid_type: UUIDChar,
) -> None:
    """Should parse string UUID via uuid.UUID constructor branch."""
    raw = "550e8400-e29b-41d4-a716-446655440000"

    result = uuid_type.process_bind_param(
        raw,
        None,  # dialect not relevant here
    )

    assert result == raw
