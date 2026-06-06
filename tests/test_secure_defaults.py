"""Secure-by-default posture tests for the 1.0.0 release.

Covers the BREAKING default changes:
- F2: ACCESS_TOKEN_ALGORITHM defaults to RS256 (HS256 is opt-in).
- F1: TOKEN_STRICT_VALIDATION on by default — iss/aud binding enforced and
      TOKEN_ISSUER/TOKEN_AUDIENCE required at boot (fail-closed).
- F3: EVENT_SIGNING_ENABLED on by default — EVENT_SIGNING_KEY required at boot.

The shared ``VALID_SETTINGS_KWARGS`` fixture pins the documented opt-out
(HS256 + permissive); these tests exercise the secure defaults instead.
"""

import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.security.factory import build_access_validator
from tests.conftest import (
    RSA_PRIVATE_PEM,
    RSA_PUBLIC_PEM,
    VALID_KEY,
    VALID_SETTINGS_KWARGS,
    IsolatedSettings,
)

ISSUER = "https://auth.example.com"
AUDIENCE = "https://api.example.com"


def _secure_kwargs(tmp_path, **overrides) -> dict:
    """Build kwargs for a secure-default issuer (RS256 + strict iss/aud).

    Starts from the shared fixture but drops the HS256/permissive opt-out
    overrides so the 1.0.0 defaults apply, then supplies RS256 key files and the
    required issuer/audience binding.
    """
    priv = tmp_path / "private.pem"
    priv.write_text(RSA_PRIVATE_PEM.strip())
    pub = tmp_path / "public.pem"
    pub.write_text(RSA_PUBLIC_PEM.strip())
    base = {
        k: v
        for k, v in VALID_SETTINGS_KWARGS.items()
        if k not in {"ACCESS_TOKEN_ALGORITHM", "TOKEN_STRICT_VALIDATION"}
    }
    base.update(
        {
            "ACCESS_SECRET_KEY": None,
            "ACCESS_PRIVATE_KEY_FILE": str(priv),
            "ACCESS_PUBLIC_KEY_FILE": str(pub),
            "TOKEN_ISSUER": ISSUER,
            "TOKEN_AUDIENCE": AUDIENCE,
        }
    )
    base.update(overrides)
    return base


def _rs256_token(*, issuer=ISSUER, audience=AUDIENCE, **extra) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "user-123",
        "type": "access",
        "email": "test@example.com",
        "role": "user",
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "is_active": True,
        "email_verified": False,
        "is_superuser": False,
    }
    if issuer is not None:
        payload["iss"] = issuer
    if audience is not None:
        payload["aud"] = audience
    payload.update(extra)
    return jwt.encode(payload, RSA_PRIVATE_PEM, algorithm="RS256")


# ── F2: RS256 is the default ──────────────────────────────────────────────────


def test_default_access_algorithm_is_rs256(tmp_path) -> None:
    s = IsolatedSettings(**_secure_kwargs(tmp_path))
    assert s.ACCESS_TOKEN_ALGORITHM == "RS256"
    assert s.TOKEN_STRICT_VALIDATION is True


def test_hs256_still_supported_as_opt_out() -> None:
    """HS256 remains fully usable when explicitly configured."""
    s = IsolatedSettings(**VALID_SETTINGS_KWARGS)  # fixture = HS256 opt-out
    assert s.ACCESS_TOKEN_ALGORITHM == "HS256"


# ── F1: strict iss/aud binding on by default ──────────────────────────────────


def test_strict_default_accepts_correctly_bound_token(tmp_path) -> None:
    s = IsolatedSettings(**_secure_kwargs(tmp_path))
    validator = build_access_validator(s)
    result = validator.validate_access_token(_rs256_token())
    assert result.sub == "user-123"


def test_strict_default_rejects_wrong_audience(tmp_path) -> None:
    s = IsolatedSettings(**_secure_kwargs(tmp_path))
    validator = build_access_validator(s)
    with pytest.raises(InvalidToken):
        validator.validate_access_token(_rs256_token(audience="https://evil.example"))


def test_strict_default_rejects_missing_issuer(tmp_path) -> None:
    s = IsolatedSettings(**_secure_kwargs(tmp_path))
    validator = build_access_validator(s)
    with pytest.raises(InvalidToken):
        validator.validate_access_token(_rs256_token(issuer=None))


def test_strict_default_requires_issuer_and_audience_at_boot(tmp_path) -> None:
    kwargs = _secure_kwargs(tmp_path)
    kwargs.pop("TOKEN_ISSUER")
    kwargs.pop("TOKEN_AUDIENCE")
    with pytest.raises(Exception, match="TOKEN_STRICT_VALIDATION=true requires"):
        IsolatedSettings(**kwargs)


def test_strict_opt_out_allows_missing_binding(tmp_path) -> None:
    """With strict disabled, missing iss/aud is allowed (single-service/dev)."""
    kwargs = _secure_kwargs(tmp_path, TOKEN_STRICT_VALIDATION=False)
    kwargs.pop("TOKEN_ISSUER")
    kwargs.pop("TOKEN_AUDIENCE")
    s = IsolatedSettings(**kwargs)
    assert s.TOKEN_STRICT_VALIDATION is False


# ── F3: event-signing key required at boot ────────────────────────────────────


def test_event_signing_enabled_requires_key(tmp_path) -> None:
    kwargs = _secure_kwargs(tmp_path)
    kwargs["EVENT_SIGNING_KEY"] = None
    with pytest.raises(Exception, match="requires EVENT_SIGNING_KEY"):
        IsolatedSettings(**kwargs)


def test_event_signing_weak_key_rejected(tmp_path) -> None:
    kwargs = _secure_kwargs(tmp_path, EVENT_SIGNING_KEY="short")
    with pytest.raises(Exception, match="EVENT_SIGNING_KEY must be a valid secret key"):
        IsolatedSettings(**kwargs)


def test_event_signing_disabled_allows_missing_key(tmp_path) -> None:
    kwargs = _secure_kwargs(
        tmp_path, EVENT_SIGNING_ENABLED=False, EVENT_SIGNING_KEY=None
    )
    s = IsolatedSettings(**kwargs)
    assert s.EVENT_SIGNING_ENABLED is False
    assert s.EVENT_SIGNING_KEY is None


def test_event_signing_key_accepted_when_strong(tmp_path) -> None:
    s = IsolatedSettings(**_secure_kwargs(tmp_path, EVENT_SIGNING_KEY=VALID_KEY))
    assert s.EVENT_SIGNING_KEY is not None
    assert s.EVENT_SIGNING_KEY.get_secret_value() == VALID_KEY
