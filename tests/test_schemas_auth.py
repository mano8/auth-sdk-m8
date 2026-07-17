"""Tests for auth_sdk_m8.schemas.auth."""

import pytest
from pydantic import SecretStr, ValidationError

from auth_sdk_m8.authorization import find_inconsistent_privilege_claims_error
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


# ── Canonical role/flag invariant (§3.1) ─────────────────────────────────────

# Every payload model inheriting UserPayloadData, with the extra fields each
# one requires. TokenAccessData is the token-creation payload and TokenUserData
# the decoded one, so creation and consumption are both covered here.
_PAYLOAD_MODELS = [
    (UserPayloadData, {}),
    (TokenAccessData, {"sub": "u", "type": "access"}),
    (TokenUserData, {"sub": "u", "type": "access", "jti": "j"}),
    (TokenPayload, {"sub": "u"}),
]
_VALID_PAIRS = [(role, role == RoleType.SUPERADMIN) for role in RoleType]
_INVALID_PAIRS = [(role, role != RoleType.SUPERADMIN) for role in RoleType]


@pytest.mark.parametrize("model,extra", _PAYLOAD_MODELS)
@pytest.mark.parametrize("role,is_superuser", _VALID_PAIRS)
def test_payload_models_accept_canonical_pairs(
    model: type, extra: dict, role: RoleType, is_superuser: bool
) -> None:
    d = model(email="a@b.com", role=role, is_superuser=is_superuser, **extra)
    assert d.role is role
    assert d.is_superuser is is_superuser


@pytest.mark.parametrize("model,extra", _PAYLOAD_MODELS)
@pytest.mark.parametrize("role,is_superuser", _INVALID_PAIRS)
def test_payload_models_reject_inconsistent_pairs(
    model: type, extra: dict, role: RoleType, is_superuser: bool
) -> None:
    with pytest.raises(ValidationError) as exc_info:
        model(email="a@b.com", role=role, is_superuser=is_superuser, **extra)

    assert find_inconsistent_privilege_claims_error(exc_info.value) is not None


def test_payload_flag_alone_cannot_claim_superuser() -> None:
    # The escalation shape the invariant exists to stop: flag set, role low.
    with pytest.raises(ValidationError):
        TokenAccessData(
            sub="u",
            type="access",
            email="a@b.com",
            role=RoleType.USER,
            is_superuser=True,
        )


def test_payload_superadmin_without_flag_is_rejected() -> None:
    with pytest.raises(ValidationError):
        TokenAccessData(
            sub="u",
            type="access",
            email="a@b.com",
            role=RoleType.SUPERADMIN,
            is_superuser=False,
        )
