"""Tests for auth_sdk_m8.core.security."""

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from pydantic import SecretStr

from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.core.security import ComSecurityHelper
from auth_sdk_m8.schemas.auth import TokenDecodeProps, TokenSecret
from tests.conftest import VALID_KEY, make_access_token, make_refresh_token

# ── decode_access_token ───────────────────────────────────────────────────────


def test_decode_access_token_valid() -> None:
    token = make_access_token()
    props = TokenDecodeProps(
        access_token=token,
        secret_key=SecretStr(VALID_KEY),
        algorithm="HS256",
    )
    with pytest.warns(DeprecationWarning, match="use TokenValidator"):
        data = ComSecurityHelper.decode_access_token(props)
    assert data.sub == "user-123"
    assert data.email == "test@example.com"


def test_decode_access_token_wrong_type() -> None:
    token = make_access_token(type="refresh")
    props = TokenDecodeProps(
        access_token=token,
        secret_key=SecretStr(VALID_KEY),
        algorithm="HS256",
    )
    with pytest.warns(DeprecationWarning, match="use TokenValidator"):
        with pytest.raises(InvalidToken, match="Not an access token"):
            ComSecurityHelper.decode_access_token(props)


def test_decode_access_token_manually_expired() -> None:
    past = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())
    props = TokenDecodeProps(
        access_token=make_access_token(exp=past),
        secret_key=SecretStr(VALID_KEY),
        algorithm="HS256",
    )
    with pytest.warns(DeprecationWarning, match="use TokenValidator"):
        with pytest.raises(InvalidToken, match="Access token expired"):
            ComSecurityHelper.decode_access_token(props)


def test_decode_access_token_invalid_signature() -> None:
    token = make_access_token(secret="wrong-secret-key")
    props = TokenDecodeProps(
        access_token=token,
        secret_key=SecretStr(VALID_KEY),
        algorithm="HS256",
    )
    with pytest.warns(DeprecationWarning, match="use TokenValidator"):
        with pytest.raises(InvalidToken, match="Invalid access token"):
            ComSecurityHelper.decode_access_token(props)


def test_decode_access_token_malformed() -> None:
    props = TokenDecodeProps(
        access_token="not.a.jwt",
        secret_key=SecretStr(VALID_KEY),
        algorithm="HS256",
    )
    with pytest.warns(DeprecationWarning, match="use TokenValidator"):
        with pytest.raises(InvalidToken):
            ComSecurityHelper.decode_access_token(props)


def test_decode_access_token_legacy_wrapper_keeps_zero_leeway() -> None:
    token = make_access_token(
        exp=int((datetime.now(timezone.utc) - timedelta(seconds=2)).timestamp())
    )
    props = TokenDecodeProps(
        access_token=token,
        secret_key=SecretStr(VALID_KEY),
        algorithm="HS256",
    )

    with pytest.warns(DeprecationWarning, match="use TokenValidator"):
        with pytest.raises(InvalidToken, match="Access token expired"):
            ComSecurityHelper.decode_access_token(props)


# ── decode_refresh_token ──────────────────────────────────────────────────────


def test_decode_refresh_token_returns_user_id() -> None:
    sub = "550e8400-e29b-41d4-a716-446655440000"
    token = make_refresh_token(sub=sub)
    secrets = TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256")
    result = ComSecurityHelper.decode_refresh_token(token, secrets)
    assert result == uuid.UUID(sub)


def test_decode_refresh_token_with_jti() -> None:
    sub = "550e8400-e29b-41d4-a716-446655440000"
    token = make_refresh_token(sub=sub)
    secrets = TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256")
    user_id, jti = ComSecurityHelper.decode_refresh_token(
        token, secrets, return_jti=True
    )
    assert user_id == uuid.UUID(sub)
    assert jti == "test-jti-0000"


def test_decode_refresh_token_wrong_type() -> None:
    token = make_refresh_token(type="access")
    secrets = TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256")
    with pytest.raises(InvalidToken, match="Not a refresh token"):
        ComSecurityHelper.decode_refresh_token(token, secrets)


def test_decode_refresh_token_invalid_signature() -> None:
    token = make_refresh_token(secret="wrong-key")
    secrets = TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256")
    with pytest.raises(InvalidToken, match="Invalid refresh token"):
        ComSecurityHelper.decode_refresh_token(token, secrets)


def test_decode_refresh_token_expired_branch() -> None:
    secrets = TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256")
    with patch("auth_sdk_m8.core.security.jwt.decode") as mock_decode:
        mock_decode.return_value = {
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "type": "refresh",
            "jti": "test-jti-0000",
            "exp": int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp()),
        }

        with pytest.raises(InvalidToken, match="Refresh token expired"):
            ComSecurityHelper.decode_refresh_token("token", secrets)


def test_decode_refresh_token_missing_jti() -> None:
    secrets = TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256")
    with patch("auth_sdk_m8.core.security.jwt.decode") as mock_decode:
        mock_decode.return_value = {
            "sub": "550e8400-e29b-41d4-a716-446655440000",
            "type": "refresh",
            "jti": None,
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
        }

        with pytest.raises(InvalidToken, match="Invalid refresh token"):
            ComSecurityHelper.decode_refresh_token("token", secrets)


# ── cookie helpers ────────────────────────────────────────────────────────────


def test_get_refresh_token_from_cookie_present() -> None:
    result = ComSecurityHelper.get_refresh_token_from_cookie("my-refresh-token")
    assert result == "my-refresh-token"


def test_get_refresh_token_from_cookie_missing() -> None:
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        ComSecurityHelper.get_refresh_token_from_cookie(None)
    assert exc_info.value.status_code == 401


def test_get_access_token_from_cookie_present() -> None:
    result = ComSecurityHelper.get_access_token_from_cookie("my-access-token")
    assert result == "my-access-token"


def test_get_access_token_from_cookie_missing() -> None:
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc_info:
        ComSecurityHelper.get_access_token_from_cookie(None)
    assert exc_info.value.status_code == 401


# ── misc helpers ──────────────────────────────────────────────────────────────


def test_hash_token_deterministic() -> None:
    h1 = ComSecurityHelper.hash_token("mytoken")
    h2 = ComSecurityHelper.hash_token("mytoken")
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


def test_hash_token_different_inputs() -> None:
    assert ComSecurityHelper.hash_token("a") != ComSecurityHelper.hash_token("b")


def test_create_state_encodes_pkce() -> None:
    import base64
    import json

    state = ComSecurityHelper.create_state("my-pkce-verifier")
    decoded = json.loads(base64.b64decode(state).decode())
    assert decoded["pkce"] == "my-pkce-verifier"


def test_create_pkce_length_and_charset() -> None:
    pkce = ComSecurityHelper.create_pkce()
    # base64url without padding: 43 chars for 32 random bytes
    assert 43 <= len(pkce) <= 128
    assert "=" not in pkce
