"""Tests for auth_sdk_m8.schemas.auth."""

import pytest
from pydantic import SecretStr, ValidationError

from auth_sdk_m8.schemas.auth import (
    ExternalTokensData,
    Token,
    TokenAccessData,
    TokenDecodeProps,
    TokenMinimalData,
    TokenPayload,
    TokenSecret,
    TokenSubData,
    TokenUserData,
    UserPayloadData,
)
from auth_sdk_m8.schemas.base import RoleType
from tests.conftest import VALID_KEY


def test_token_defaults() -> None:
    t = Token(access_token="abc123")
    assert t.access_token == "abc123"
    assert t.token_type == "bearer"


def test_token_custom_type() -> None:
    t = Token(access_token="abc", token_type="jwt")
    assert t.token_type == "jwt"


def test_token_decode_props() -> None:
    props = TokenDecodeProps(
        access_token="tok",
        secret_key=SecretStr(VALID_KEY),
        algorithm="HS256",
    )
    assert props.access_token == "tok"


def test_token_secret_valid() -> None:
    ts = TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256")
    assert ts.algorithm == "HS256"


def test_token_secret_invalid_key() -> None:
    with pytest.raises(ValidationError, match="Invalid secret key format"):
        TokenSecret(secret_key=SecretStr("tooshort"), algorithm="HS256")


def test_external_tokens_data() -> None:
    d = ExternalTokensData(
        expires=9999,
        access=SecretStr("access-tok"),
        refresh=SecretStr("refresh-tok"),
    )
    assert d.expires == 9999


def test_token_sub_data() -> None:
    d = TokenSubData(sub="user-123")
    assert d.sub == "user-123"


def test_user_payload_data_defaults() -> None:
    d = UserPayloadData(email="a@b.com")
    assert d.is_active is True
    assert d.email_verified is False
    assert d.is_superuser is False
    assert d.role == RoleType.USER
    assert d.full_name is None
    assert d.avatar is None


def test_token_minimal_data() -> None:
    d = TokenMinimalData(sub="u", type="refresh")
    assert d.type == "refresh"


def test_token_minimal_data_default_type() -> None:
    d = TokenMinimalData(sub="u")
    assert d.type == "access"


def test_token_access_data() -> None:
    d = TokenAccessData(sub="u", email="a@b.com", type="access")
    assert d.sub == "u"


def test_token_user_data_with_exp() -> None:
    d = TokenUserData(
        sub="u",
        email="a@b.com",
        jti="some-jti",
        exp=9999999999,
        type="access",
    )
    assert d.exp == 9999999999
    assert d.jti == "some-jti"


def test_token_user_data_exp_defaults_none() -> None:
    d = TokenUserData(sub="u", email="a@b.com", jti="j", type="access")
    assert d.exp is None


def test_token_payload() -> None:
    d = TokenPayload(sub="u", email="a@b.com")
    assert d.sub == "u"
    assert d.role == RoleType.USER


# ── Asymmetric key support ───────────────────────────────────────────────────


def test_token_secret_rs256_accepts_pem_key() -> None:
    # PEM public keys don't match SECRET_KEY_REGEX — must be allowed for RS256.
    pem = (
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n"
        "-----END PUBLIC KEY-----"
    )
    ts = TokenSecret(secret_key=SecretStr(pem), algorithm="RS256")
    assert ts.algorithm == "RS256"
    assert ts.secret_key.get_secret_value() == pem


def test_token_secret_es256_accepts_pem_key() -> None:
    pem = (
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n"
        "-----END PUBLIC KEY-----"
    )
    ts = TokenSecret(secret_key=SecretStr(pem), algorithm="ES256")
    assert ts.algorithm == "ES256"


def test_token_secret_hs256_still_validates_strength() -> None:
    with pytest.raises(ValidationError, match="Invalid secret key format"):
        TokenSecret(secret_key=SecretStr("weak"), algorithm="HS256")


def test_token_secret_es256_is_valid_algorithm() -> None:
    # Verifies that ES256 is accepted as a TokenAlgorithm literal.
    pem = "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----"
    ts = TokenSecret(secret_key=SecretStr(pem), algorithm="ES256")
    assert ts.algorithm == "ES256"
