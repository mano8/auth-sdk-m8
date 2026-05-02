"""Tests for auth_sdk_m8.utils.errors_parser and auth_sdk_m8.utils.paths."""
import pytest
from pathlib import Path
from pydantic import BaseModel, ValidationError
from sqlalchemy.exc import IntegrityError

from auth_sdk_m8.utils.errors_parser import parse_integrity_error, parse_pydantic_errors
from auth_sdk_m8.utils.paths import find_dotenv


# ── helpers ───────────────────────────────────────────────────────────────────

def _make_integrity_error(msg: str) -> IntegrityError:
    return IntegrityError(statement="INSERT INTO t", params={}, orig=Exception(msg))


# ── parse_integrity_error ─────────────────────────────────────────────────────

def test_parse_integrity_error_unique_constraint() -> None:
    exc = _make_integrity_error(
        "Duplicate entry 'user@mail.com' for key 'users.email'"
    )
    errors = parse_integrity_error(exc)
    assert len(errors) == 1
    assert errors[0]["table"] == "users"
    assert errors[0]["field_name"] == "email"
    assert "Duplicate entry" in errors[0]["error"]


def test_parse_integrity_error_foreign_key() -> None:
    exc = _make_integrity_error(
        "FOREIGN KEY (`user_id`) REFERENCES `users`"
    )
    errors = parse_integrity_error(exc)
    assert len(errors) == 1
    assert errors[0]["table"] == "users"
    assert errors[0]["field_name"] == "user_id"
    assert "foreign key" in errors[0]["error"]


def test_parse_integrity_error_not_null() -> None:
    exc = _make_integrity_error("Column 'email' cannot be null")
    errors = parse_integrity_error(exc)
    assert len(errors) == 1
    assert errors[0]["field_name"] == "email"
    assert errors[0]["table"] is None
    assert "cannot be null" in errors[0]["error"]


def test_parse_integrity_error_no_default() -> None:
    exc = _make_integrity_error("Field 'username' doesn't have a default value")
    errors = parse_integrity_error(exc)
    assert len(errors) == 1
    assert errors[0]["field_name"] == "username"
    assert "requires a value" in errors[0]["error"]


def test_parse_integrity_error_unknown() -> None:
    exc = _make_integrity_error("Some completely unknown DB error")
    errors = parse_integrity_error(exc)
    assert len(errors) == 1
    assert errors[0]["error"] == "Unknown database integrity error"
    assert errors[0]["table"] is None
    assert errors[0]["field_name"] is None


# ── PostgreSQL patterns ───────────────────────────────────────────────────────

def test_parse_integrity_error_pg_unique() -> None:
    exc = _make_integrity_error(
        'duplicate key value violates unique constraint "users_email_key"\n'
        "DETAIL:  Key (email)=(user@example.com) already exists.\n"
    )
    errors = parse_integrity_error(exc)
    assert len(errors) == 1
    assert errors[0]["field_name"] == "email"
    assert "Duplicate entry" in errors[0]["error"]


def test_parse_integrity_error_pg_foreign_key() -> None:
    exc = _make_integrity_error(
        'insert or update on table "orders" violates foreign key constraint "orders_user_id_fkey"\n'
        "DETAIL:  Key (user_id)=(999) is not present in table \"users\".\n"
    )
    errors = parse_integrity_error(exc)
    assert len(errors) == 1
    assert errors[0]["field_name"] == "user_id"
    assert errors[0]["table"] == "users"
    assert "foreign key" in errors[0]["error"]


def test_parse_integrity_error_pg_not_null() -> None:
    exc = _make_integrity_error(
        'null value in column "email" of relation "users" violates not-null constraint\n'
        "DETAIL:  Failing row contains (1, null, active).\n"
    )
    errors = parse_integrity_error(exc)
    assert len(errors) == 1
    assert errors[0]["field_name"] == "email"
    assert errors[0]["table"] == "users"
    assert "cannot be null" in errors[0]["error"]


def test_parse_integrity_error_multiple_matches() -> None:
    msg = (
        "Duplicate entry 'a@b.com' for key 'users.email' "
        "Column 'name' cannot be null"
    )
    exc = _make_integrity_error(msg)
    errors = parse_integrity_error(exc)
    assert len(errors) == 2


# ── parse_pydantic_errors ─────────────────────────────────────────────────────

class _DummyModel(BaseModel):
    x: int
    y: str


def test_parse_pydantic_errors_single_field() -> None:
    try:
        _DummyModel(x="not-an-int", y="ok")  # type: ignore[arg-type]
    except ValidationError as exc:
        errors = parse_pydantic_errors(exc)
    assert len(errors) >= 1
    assert errors[0]["field_name"] == "x"
    assert errors[0]["error"]


def test_parse_pydantic_errors_multiple_fields() -> None:
    try:
        _DummyModel(x="bad", y=None)  # type: ignore[arg-type]
    except ValidationError as exc:
        errors = parse_pydantic_errors(exc)
    assert len(errors) >= 1


# ── find_dotenv ───────────────────────────────────────────────────────────────

def test_find_dotenv_found_in_same_dir(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("KEY=value")
    result = find_dotenv(tmp_path)
    assert Path(result).name == ".env"


def test_find_dotenv_found_in_parent(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("KEY=value")
    subdir = tmp_path / "subdir"
    subdir.mkdir()
    result = find_dotenv(subdir)
    assert Path(result).name == ".env"


def test_find_dotenv_not_found(tmp_path: Path) -> None:
    empty = tmp_path / "a" / "b"
    empty.mkdir(parents=True)
    with pytest.raises(FileNotFoundError, match=".env file not found"):
        find_dotenv(empty)


def test_find_dotenv_start_is_file(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("KEY=value")
    some_file = tmp_path / "app.py"
    some_file.write_text("x = 1")
    result = find_dotenv(some_file)
    assert Path(result).name == ".env"
