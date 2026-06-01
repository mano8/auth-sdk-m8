"""Tests for utils/email.py."""

from auth_sdk_m8.utils.email import normalize_email


def test_normalize_email_lowercases() -> None:
    assert normalize_email("User@Example.COM") == "user@example.com"


def test_normalize_email_strips_whitespace() -> None:
    assert normalize_email("  user@example.com  ") == "user@example.com"


def test_normalize_email_both() -> None:
    assert normalize_email("  User@Example.COM  ") == "user@example.com"


def test_normalize_email_already_normalised() -> None:
    assert normalize_email("user@example.com") == "user@example.com"


def test_normalize_email_preserves_plus_tags() -> None:
    assert normalize_email("User+Tag@Example.com") == "user+tag@example.com"


def test_normalize_email_preserves_dots() -> None:
    assert normalize_email("First.Last@Example.com") == "first.last@example.com"
