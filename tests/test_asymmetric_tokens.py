"""
RS256 and ES256 sign → encode → decode → validate round-trip tests.

The existing test_security_token_validator.py covers HS256 and the key-resolver
protocol exhaustively with synthetic tokens.  This file fills the gap: it uses
real PyJWT encoding with the RSA/EC PEM keys so that the cryptographic path —
not just the validator logic — is exercised in isolation, without a running service.

Covered here (not elsewhere):
- RS256 and ES256 complete sign → validate round-trips via TokenValidator
- Wrong-key and cross-algorithm rejection for both asymmetric algorithms
- build_access_validator factory: RS256 static-key path actually validates
- build_access_validator factory: ES256 static-key path actually validates
- build_access_validator factory: JWKS-resolver path wires correctly and validates
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Tuple
from unittest.mock import MagicMock, patch

import jwt
import pytest
from pydantic import SecretStr

from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.auth import TokenSecret
from auth_sdk_m8.security.factory import build_access_validator
from auth_sdk_m8.security.token_validator import TokenValidator
from auth_sdk_m8.security.validation import TokenValidationConfig
from tests.conftest import RSA_PRIVATE_PEM, RSA_PUBLIC_PEM, VALID_KEY

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(scope="module")
def ec_keypair() -> Tuple[str, str]:
    """Fresh P-256 keypair for ES256 tests (generated once per module)."""
    from cryptography.hazmat.primitives.asymmetric.ec import (
        SECP256R1,
        generate_private_key,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    priv = generate_private_key(SECP256R1())
    priv_pem = priv.private_bytes(
        Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()
    ).decode()
    pub_pem = (
        priv.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return priv_pem, pub_pem


@pytest.fixture(scope="module")
def rsa_keypair_b() -> Tuple[str, str]:
    """Second RSA keypair for wrong-key rejection tests."""
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    priv = generate_private_key(65537, 2048, default_backend())
    priv_pem = priv.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    ).decode()
    pub_pem = (
        priv.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return priv_pem, pub_pem


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_token(
    private_pem: str,
    algorithm: str,
    *,
    expired: bool = False,
    token_type: str = "access",
    kid: str | None = None,
    **extra,
) -> str:
    now = datetime.now(timezone.utc)
    exp = now - timedelta(minutes=10) if expired else now + timedelta(hours=1)
    payload = {
        "sub": "user-123",
        "type": token_type,
        "email": "test@example.com",
        "role": "user",
        "jti": str(uuid.uuid4()),
        "exp": int(exp.timestamp()),
        "is_active": True,
        "email_verified": False,
        "is_superuser": False,
        **extra,
    }
    headers = {"kid": kid} if kid else None
    return jwt.encode(payload, private_pem, algorithm=algorithm, headers=headers)


def _validator(public_pem: str, algorithm: str) -> TokenValidator:
    return TokenValidator(
        secrets=TokenSecret(secret_key=SecretStr(public_pem), algorithm=algorithm),
        config=TokenValidationConfig(allowed_algorithms=[algorithm]),
    )


# ── RS256 round-trip ──────────────────────────────────────────────────────────


def test_rs256_valid_token_validates() -> None:
    token = _make_token(RSA_PRIVATE_PEM, "RS256")
    result = _validator(RSA_PUBLIC_PEM, "RS256").validate_access_token(token)
    assert result.sub == "user-123"
    assert result.email == "test@example.com"


def test_rs256_user_fields_preserved() -> None:
    token = _make_token(RSA_PRIVATE_PEM, "RS256", full_name="Alice", is_superuser=True)
    result = _validator(RSA_PUBLIC_PEM, "RS256").validate_access_token(token)
    assert result.full_name == "Alice"
    assert result.is_superuser is True


def test_rs256_expired_token_raises() -> None:
    token = _make_token(RSA_PRIVATE_PEM, "RS256", expired=True)
    with pytest.raises(InvalidToken, match="expired"):
        _validator(RSA_PUBLIC_PEM, "RS256").validate_access_token(token)


def test_rs256_wrong_public_key_raises(rsa_keypair_b: Tuple[str, str]) -> None:
    _, other_pub = rsa_keypair_b
    token = _make_token(RSA_PRIVATE_PEM, "RS256")
    with pytest.raises(InvalidToken):
        _validator(other_pub, "RS256").validate_access_token(token)


def test_rs256_wrong_token_type_raises() -> None:
    token = _make_token(RSA_PRIVATE_PEM, "RS256", token_type="refresh")
    with pytest.raises(InvalidToken, match="Not an access token"):
        _validator(RSA_PUBLIC_PEM, "RS256").validate_access_token(token)


def test_rs256_validator_rejects_hs256_token() -> None:
    """RS256 validator must reject a token signed with HS256."""
    hs256_token = _make_token(VALID_KEY, "HS256")
    with pytest.raises(InvalidToken):
        _validator(RSA_PUBLIC_PEM, "RS256").validate_access_token(hs256_token)


# ── ES256 round-trip ──────────────────────────────────────────────────────────


def test_es256_valid_token_validates(ec_keypair: Tuple[str, str]) -> None:
    priv_pem, pub_pem = ec_keypair
    token = _make_token(priv_pem, "ES256")
    result = _validator(pub_pem, "ES256").validate_access_token(token)
    assert result.sub == "user-123"
    assert result.email == "test@example.com"


def test_es256_expired_token_raises(ec_keypair: Tuple[str, str]) -> None:
    priv_pem, pub_pem = ec_keypair
    token = _make_token(priv_pem, "ES256", expired=True)
    with pytest.raises(InvalidToken, match="expired"):
        _validator(pub_pem, "ES256").validate_access_token(token)


def test_es256_wrong_public_key_raises(
    ec_keypair: Tuple[str, str], rsa_keypair_b: Tuple[str, str]
) -> None:
    """ES256 token validated against an RSA public key must be rejected."""
    priv_pem, _ = ec_keypair
    _, rsa_pub = rsa_keypair_b
    token = _make_token(priv_pem, "ES256")
    with pytest.raises(InvalidToken):
        _validator(rsa_pub, "ES256").validate_access_token(token)


def test_es256_validator_rejects_rs256_token(ec_keypair: Tuple[str, str]) -> None:
    """ES256 validator must reject a token signed with RS256."""
    _, pub_pem = ec_keypair
    token = _make_token(RSA_PRIVATE_PEM, "RS256")
    with pytest.raises(InvalidToken):
        _validator(pub_pem, "ES256").validate_access_token(token)


# ── build_access_validator — asymmetric static-key path ──────────────────────


def _asymmetric_settings(**overrides) -> MagicMock:
    """Minimal mock settings for build_access_validator asymmetric path."""
    s = MagicMock()
    del s.TOKEN_ISSUER
    del s.TOKEN_AUDIENCE
    del s.JWKS_URI
    for k, v in overrides.items():
        setattr(s, k, v)
    return s


def test_factory_rs256_static_key_validates() -> None:
    settings = _asymmetric_settings(
        ACCESS_TOKEN_ALGORITHM="RS256",
        ACCESS_PUBLIC_KEY=RSA_PUBLIC_PEM,
        ACCESS_SECRET_KEY=None,
    )
    validator = build_access_validator(settings)
    token = _make_token(RSA_PRIVATE_PEM, "RS256")
    result = validator.validate_access_token(token)
    assert result.sub == "user-123"


def test_factory_es256_static_key_validates(ec_keypair: Tuple[str, str]) -> None:
    priv_pem, pub_pem = ec_keypair
    settings = _asymmetric_settings(
        ACCESS_TOKEN_ALGORITHM="ES256",
        ACCESS_PUBLIC_KEY=pub_pem,
        ACCESS_SECRET_KEY=None,
    )
    validator = build_access_validator(settings)
    token = _make_token(priv_pem, "ES256")
    result = validator.validate_access_token(token)
    assert result.sub == "user-123"


# ── build_access_validator — JWKS-resolver path ───────────────────────────────


def test_factory_rs256_jwks_resolver_validates() -> None:
    """JWKS path: resolver returns the known public key; token validates."""
    token = _make_token(RSA_PRIVATE_PEM, "RS256", kid="key-1")

    mock_resolver = MagicMock()
    mock_resolver.resolve.return_value = TokenSecret(
        secret_key=SecretStr(RSA_PUBLIC_PEM),
        algorithm="RS256",
    )

    settings = MagicMock()
    settings.ACCESS_TOKEN_ALGORITHM = "RS256"
    settings.JWKS_URI = "https://auth.example.com/.well-known/jwks.json"
    settings.JWKS_CACHE_TTL_SECONDS = 300
    del settings.TOKEN_ISSUER
    del settings.TOKEN_AUDIENCE

    with patch(
        "auth_sdk_m8.security.jwks_resolver.JwksKeyResolver", return_value=mock_resolver
    ):
        validator = build_access_validator(settings)

    result = validator.validate_access_token(token)
    assert result.sub == "user-123"
    mock_resolver.resolve.assert_called_once_with("key-1")


def test_factory_rs256_jwks_unknown_kid_raises() -> None:
    """JWKS path: resolver that cannot find the kid raises InvalidToken."""
    token = _make_token(RSA_PRIVATE_PEM, "RS256", kid="unknown-kid")

    mock_resolver = MagicMock()
    mock_resolver.resolve.side_effect = LookupError("No key with kid='unknown-kid'")

    settings = MagicMock()
    settings.ACCESS_TOKEN_ALGORITHM = "RS256"
    settings.JWKS_URI = "https://auth.example.com/.well-known/jwks.json"
    settings.JWKS_CACHE_TTL_SECONDS = 300
    del settings.TOKEN_ISSUER
    del settings.TOKEN_AUDIENCE

    with patch(
        "auth_sdk_m8.security.jwks_resolver.JwksKeyResolver", return_value=mock_resolver
    ):
        validator = build_access_validator(settings)

    with pytest.raises(InvalidToken):
        validator.validate_access_token(token)
