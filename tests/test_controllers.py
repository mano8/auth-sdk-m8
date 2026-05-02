"""Tests for auth_sdk_m8.controllers.base."""
from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel, ValidationError
from sqlalchemy.exc import IntegrityError

from auth_sdk_m8.controllers.base import BaseController


def _make_integrity_error(msg: str) -> IntegrityError:
    return IntegrityError(statement="INSERT", params={}, orig=Exception(msg))


class _DummyModel(BaseModel):
    x: int


def _make_validation_error() -> ValidationError:
    try:
        _DummyModel(x="bad")  # type: ignore[arg-type]
    except ValidationError as exc:
        return exc
    raise AssertionError("expected ValidationError")


def test_get_error_responses() -> None:
    responses = BaseController.get_error_responses()
    assert 500 in responses


def test_handle_integrity_error_with_session() -> None:
    exc = _make_integrity_error(
        "Duplicate entry 'a@b.com' for key 'users.email'"
    )
    session = MagicMock()
    response = BaseController.handle_exception(exc, session)
    session.rollback.assert_called_once()
    assert response.status_code == 500
    body = response.body
    assert b"integrity" in body.lower() or b"duplicate" in body.lower() or b"database" in body.lower()


def test_handle_validation_error_no_session() -> None:
    exc = _make_validation_error()
    response = BaseController.handle_exception(exc)
    assert response.status_code == 500
    assert b"Validation" in response.body


def test_handle_value_error() -> None:
    response = BaseController.handle_exception(ValueError("bad value"))
    assert response.status_code == 500
    assert b"Internal" in response.body


def test_handle_type_error() -> None:
    response = BaseController.handle_exception(TypeError("type issue"))
    assert response.status_code == 500


def test_handle_io_error() -> None:
    response = BaseController.handle_exception(IOError("file error"))
    assert response.status_code == 500


def test_handle_generic_exception() -> None:
    response = BaseController.handle_exception(RuntimeError("oops"))
    assert response.status_code == 500
    assert b"unexpected" in response.body.lower()


def test_handle_exception_no_session_no_rollback() -> None:
    exc = ValueError("no session")
    response = BaseController.handle_exception(exc, None)
    assert response.status_code == 500


def test_handle_exception_rolls_back_session() -> None:
    session = MagicMock()
    BaseController.handle_exception(RuntimeError("err"), session)
    session.rollback.assert_called_once()
