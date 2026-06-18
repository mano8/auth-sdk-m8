"""Phase 1.0 — baseline security-validator regression tests.

Codifies what is already true in CommonSettings so the security invariants
cannot silently regress.  No new production code is introduced; every
assertion reflects current behaviour.

Invariants locked in:
- All fields in secret_fields reject the literal "changethis" placeholder.
- Password fields enforce the PASSWORD_REGEX strength rule (8+ chars, upper,
  lower, digit, special, no spaces).
- Secret-key fields enforce the SECRET_KEY_REGEX strength rule (32+ chars,
  upper, lower, digit, non-alphanumeric, no spaces).
- EVENT_SIGNING_ENABLED=true requires a strong EVENT_SIGNING_KEY at boot.
- TOKEN_STRICT_VALIDATION=true requires TOKEN_ISSUER and TOKEN_AUDIENCE
  at boot (fail-closed, not silently permissive).
- Error messages are operator-actionable (name the field, state the fix).
"""

from typing import ClassVar, Optional

import pytest

from tests.conftest import VALID_SETTINGS_KWARGS, IsolatedSettings


# ── changethis / placeholder rejection ───────────────────────────────────────
# All four secret_fields must refuse the insecure-default placeholder.  The
# specific error message varies (regex check fires before the insecure-default
# check for strongly-typed fields) — either "Insecure default" or the regex
# failure message is acceptable; what matters is that an exception is raised.


@pytest.mark.parametrize(
    "field,match",
    [
        ("DB_PASSWORD", "Insecure default|strong password"),
        ("REDIS_PASSWORD", "Insecure default|strong password"),
    ],
)
def test_changethis_rejected_for_password_fields(field: str, match: str) -> None:
    """Password fields must not accept the 'changethis' placeholder."""
    with pytest.raises(Exception, match=match):
        IsolatedSettings(**{**VALID_SETTINGS_KWARGS, field: "changethis"})


@pytest.mark.parametrize(
    "field",
    ["ACCESS_SECRET_KEY", "REFRESH_SECRET_KEY"],
)
def test_changethis_rejected_for_secret_key_fields(field: str) -> None:
    """Secret-key fields must not accept the 'changethis' placeholder."""
    with pytest.raises(Exception, match="valid secret key|Insecure default"):
        IsolatedSettings(**{**VALID_SETTINGS_KWARGS, field: "changethis"})


def test_insecure_default_branch_is_operator_actionable() -> None:
    """The 'Insecure default' message must name the affected field clearly."""

    class _PlainSecretSettings(IsolatedSettings):
        CUSTOM_TOKEN: Optional[str] = None
        required_fields: ClassVar = []
        secret_fields: ClassVar = ["CUSTOM_TOKEN"]
        passwords: ClassVar = []
        secret_keys: ClassVar = []

    with pytest.raises(Exception) as exc_info:
        _PlainSecretSettings(**{**VALID_SETTINGS_KWARGS, "CUSTOM_TOKEN": "changethis"})
    msg = str(exc_info.value)
    assert "Insecure default" in msg
    assert "CUSTOM_TOKEN" in msg


# ── password strength validation ──────────────────────────────────────────────


@pytest.mark.parametrize(
    "field,weak",
    [
        ("DB_PASSWORD", "tooshort"),      # < 8 chars
        ("DB_PASSWORD", "alllowercase1!"),  # no upper
        ("DB_PASSWORD", "ALLUPPER1!"),    # no lower
        ("DB_PASSWORD", "NoDigitHere!"),  # no digit
        ("DB_PASSWORD", "NoSpecial1"),    # no special char
        ("REDIS_PASSWORD", "weak"),       # fails on length too
    ],
)
def test_weak_password_rejected(field: str, weak: str) -> None:
    """Fields in CommonSettings.passwords must enforce the PASSWORD_REGEX rule."""
    with pytest.raises(Exception, match="strong password"):
        IsolatedSettings(**{**VALID_SETTINGS_KWARGS, field: weak})


def test_password_error_mentions_requirements() -> None:
    """Password validation error must describe the strength requirements."""
    with pytest.raises(Exception) as exc_info:
        IsolatedSettings(**{**VALID_SETTINGS_KWARGS, "DB_PASSWORD": "weak"})
    msg = str(exc_info.value)
    assert "strong password" in msg.lower() or "8" in msg


# ── secret-key strength validation ────────────────────────────────────────────


@pytest.mark.parametrize(
    "field,weak",
    [
        ("ACCESS_SECRET_KEY", "short"),
        ("ACCESS_SECRET_KEY", "a" * 32),          # long but no upper/digit/special
        ("ACCESS_SECRET_KEY", "MixedCase1234567890123456789012"),  # 31 chars, missing special
        ("REFRESH_SECRET_KEY", "short"),
        ("REFRESH_SECRET_KEY", "alllowercase1234567890no-special"),  # no upper/special
    ],
)
def test_weak_secret_key_rejected(field: str, weak: str) -> None:
    """Fields in CommonSettings.secret_keys must enforce the SECRET_KEY_REGEX rule."""
    with pytest.raises(Exception, match="valid secret key"):
        IsolatedSettings(**{**VALID_SETTINGS_KWARGS, field: weak})


def test_secret_key_error_mentions_field() -> None:
    """Secret-key validation error must be operator-actionable (mentions 'secret key')."""
    with pytest.raises(Exception) as exc_info:
        IsolatedSettings(**{**VALID_SETTINGS_KWARGS, "ACCESS_SECRET_KEY": "tooshort"})
    msg = str(exc_info.value)
    assert "secret key" in msg.lower()


# ── event-signing key requirement ─────────────────────────────────────────────


def test_event_signing_enabled_without_key_raises() -> None:
    """EVENT_SIGNING_ENABLED=true must fail at boot when EVENT_SIGNING_KEY is None."""
    with pytest.raises(Exception, match="requires EVENT_SIGNING_KEY"):
        IsolatedSettings(**{**VALID_SETTINGS_KWARGS, "EVENT_SIGNING_KEY": None})


def test_event_signing_enabled_with_empty_string_raises() -> None:
    """EVENT_SIGNING_ENABLED=true must fail at boot when EVENT_SIGNING_KEY is blank."""
    with pytest.raises(Exception, match="requires EVENT_SIGNING_KEY|valid secret key"):
        IsolatedSettings(**{**VALID_SETTINGS_KWARGS, "EVENT_SIGNING_KEY": "   "})


def test_event_signing_enabled_with_weak_key_raises() -> None:
    """A key that fails SECRET_KEY_REGEX must be rejected even when signing is enabled."""
    with pytest.raises(Exception, match="EVENT_SIGNING_KEY must be a valid secret key"):
        IsolatedSettings(**{**VALID_SETTINGS_KWARGS, "EVENT_SIGNING_KEY": "tooweak"})


def test_event_signing_disabled_allows_missing_key() -> None:
    """EVENT_SIGNING_ENABLED=false must allow EVENT_SIGNING_KEY=None (opt-out path)."""
    s = IsolatedSettings(
        **{
            **VALID_SETTINGS_KWARGS,
            "EVENT_SIGNING_ENABLED": False,
            "EVENT_SIGNING_KEY": None,
        }
    )
    assert s.EVENT_SIGNING_ENABLED is False
    assert s.EVENT_SIGNING_KEY is None


# ── TOKEN_STRICT_VALIDATION — issuer/audience required at boot ────────────────


def test_strict_validation_requires_token_issuer() -> None:
    """TOKEN_STRICT_VALIDATION=true without TOKEN_ISSUER must fail at boot."""
    with pytest.raises(Exception, match="TOKEN_STRICT_VALIDATION=true requires"):
        IsolatedSettings(
            **{
                **VALID_SETTINGS_KWARGS,
                "TOKEN_STRICT_VALIDATION": True,
                "TOKEN_AUDIENCE": "https://api.example.com",
                # TOKEN_ISSUER deliberately absent
            }
        )


def test_strict_validation_requires_token_audience() -> None:
    """TOKEN_STRICT_VALIDATION=true without TOKEN_AUDIENCE must fail at boot."""
    with pytest.raises(Exception, match="TOKEN_STRICT_VALIDATION=true requires"):
        IsolatedSettings(
            **{
                **VALID_SETTINGS_KWARGS,
                "TOKEN_STRICT_VALIDATION": True,
                "TOKEN_ISSUER": "https://auth.example.com",
                # TOKEN_AUDIENCE deliberately absent
            }
        )


def test_strict_validation_requires_both_issuer_and_audience() -> None:
    """TOKEN_STRICT_VALIDATION=true without either claim must fail at boot."""
    with pytest.raises(Exception, match="TOKEN_STRICT_VALIDATION=true requires"):
        IsolatedSettings(**{**VALID_SETTINGS_KWARGS, "TOKEN_STRICT_VALIDATION": True})


def test_strict_validation_passes_when_both_claims_set() -> None:
    """TOKEN_STRICT_VALIDATION=true is valid when both TOKEN_ISSUER and TOKEN_AUDIENCE are set."""
    s = IsolatedSettings(
        **{
            **VALID_SETTINGS_KWARGS,
            "TOKEN_STRICT_VALIDATION": True,
            "TOKEN_ISSUER": "https://auth.example.com",
            "TOKEN_AUDIENCE": "https://api.example.com",
        }
    )
    assert s.TOKEN_STRICT_VALIDATION is True
    assert s.TOKEN_ISSUER == "https://auth.example.com"
    assert s.TOKEN_AUDIENCE == "https://api.example.com"


def test_strict_validation_off_allows_missing_claims() -> None:
    """TOKEN_STRICT_VALIDATION=false must allow missing TOKEN_ISSUER/TOKEN_AUDIENCE."""
    s = IsolatedSettings(**{**VALID_SETTINGS_KWARGS, "TOKEN_STRICT_VALIDATION": False})
    assert s.TOKEN_STRICT_VALIDATION is False
    assert s.TOKEN_ISSUER is None
    assert s.TOKEN_AUDIENCE is None


def test_strict_validation_error_message_mentions_both_fields() -> None:
    """The boot error for strict validation must name both missing fields."""
    with pytest.raises(Exception) as exc_info:
        IsolatedSettings(**{**VALID_SETTINGS_KWARGS, "TOKEN_STRICT_VALIDATION": True})
    msg = str(exc_info.value)
    assert "TOKEN_ISSUER" in msg
    assert "TOKEN_AUDIENCE" in msg
