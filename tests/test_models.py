"""Tests for auth_sdk_m8.models.shared."""
from datetime import datetime

import pytest

from auth_sdk_m8.models.shared import Message, Token, TokenPayload


def test_message() -> None:
    m = Message(message="hello world")
    assert m.message == "hello world"


def test_token_defaults() -> None:
    t = Token(access_token="abc123")
    assert t.access_token == "abc123"
    assert t.token_type == "bearer"


def test_token_custom_type() -> None:
    t = Token(access_token="x", token_type="jwt")
    assert t.token_type == "jwt"


def test_token_payload_defaults() -> None:
    p = TokenPayload()
    assert p.sub is None


def test_token_payload_with_sub() -> None:
    p = TokenPayload(sub="user-123")
    assert p.sub == "user-123"
