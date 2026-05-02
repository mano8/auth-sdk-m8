"""Tests for auth_sdk_m8.core.exceptions."""
import pytest

from auth_sdk_m8.core.exceptions import InvalidToken


def test_invalid_token_is_exception() -> None:
    assert issubclass(InvalidToken, Exception)


def test_invalid_token_raises_and_catches() -> None:
    with pytest.raises(InvalidToken, match="bad token"):
        raise InvalidToken("bad token")


def test_invalid_token_preserves_cause() -> None:
    cause = ValueError("original")
    with pytest.raises(InvalidToken):
        try:
            raise cause
        except ValueError as e:
            raise InvalidToken("wrapped") from e


def test_invalid_token_no_message() -> None:
    exc = InvalidToken()
    assert isinstance(exc, InvalidToken)
