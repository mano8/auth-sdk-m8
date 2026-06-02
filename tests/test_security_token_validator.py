"""Tests for auth_sdk_m8.security.token_validator."""

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from pydantic import SecretStr

from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.auth import TokenSecret
from auth_sdk_m8.security import (
    KeyResolver,
    TokenValidationConfig,
    TokenValidator,
)
from tests.conftest import VALID_KEY, WRONG_KEY, make_access_token

ROTATED_KEY = "Bcdefg-2345_ABC-bcdefg-hijklm-nopqrs-tuvwxy"


def _encode_access(
    payload: dict,
    secret: str = VALID_KEY,
    headers: dict | None = None,
) -> str:
    return jwt.encode(payload, secret, algorithm="HS256", headers=headers)


class _MapResolver(KeyResolver):
    def __init__(self, mapping: dict[str | None, TokenSecret]) -> None:
        self.mapping = mapping
        self.calls: list[str | None] = []

    def resolve(self, kid: str | None) -> TokenSecret:
        self.calls.append(kid)
        if kid not in self.mapping:
            raise KeyError(kid)
        return self.mapping[kid]


def test_validate_access_token_valid() -> None:
    validator = TokenValidator(
        secrets=TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256"),
        config=TokenValidationConfig(),
    )

    payload = validator.validate_access_token(make_access_token())

    assert payload.sub == "user-123"
    assert payload.email == "test@example.com"


def test_validate_access_token_expired() -> None:
    validator = TokenValidator(
        secrets=TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256"),
        config=TokenValidationConfig(leeway_seconds=0),
    )
    past = int((datetime.now(timezone.utc) - timedelta(minutes=1)).timestamp())
    token = make_access_token(exp=past)

    with pytest.raises(InvalidToken, match="Access token expired"):
        validator.validate_access_token(token)


def test_validate_access_token_missing_required_claim() -> None:
    validator = TokenValidator(
        secrets=TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256"),
        config=TokenValidationConfig(),
    )
    token = _encode_access(
        {
            "sub": "user-123",
            "type": "access",
            "email": "test@example.com",
            "role": "user",
            "jti": "test-jti-0000",
            "is_active": True,
            "email_verified": False,
            "is_superuser": False,
        }
    )

    with pytest.raises(InvalidToken, match="Invalid access token"):
        validator.validate_access_token(token)


def test_validate_access_token_invalid_signature() -> None:
    validator = TokenValidator(
        secrets=TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256"),
        config=TokenValidationConfig(),
    )

    with pytest.raises(InvalidToken, match="Invalid access token"):
        validator.validate_access_token(make_access_token(secret=WRONG_KEY))


def test_validate_access_token_invalid_payload_structure() -> None:
    validator = TokenValidator(
        secrets=TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256"),
        config=TokenValidationConfig(),
    )
    token = make_access_token(email="not-an-email")

    with pytest.raises(InvalidToken, match="Invalid access token"):
        validator.validate_access_token(token)


def test_validate_access_token_wrong_type() -> None:
    validator = TokenValidator(
        secrets=TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256"),
        config=TokenValidationConfig(),
    )

    with pytest.raises(InvalidToken, match="Not an access token"):
        validator.validate_access_token(make_access_token(type="refresh"))


def test_validate_access_token_permissive_mode_ignores_issuer_and_audience() -> None:
    validator = TokenValidator(
        secrets=TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256"),
        config=TokenValidationConfig(
            issuer="auth.service",
            audience=["service-a"],
            require_iss=False,
            require_aud=False,
        ),
    )

    payload = validator.validate_access_token(make_access_token())

    assert payload.sub == "user-123"


def test_validate_access_token_strict_issuer_missing() -> None:
    validator = TokenValidator(
        secrets=TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256"),
        config=TokenValidationConfig(
            issuer="auth.service",
            require_iss=True,
        ),
    )

    with pytest.raises(InvalidToken, match="Invalid access token"):
        validator.validate_access_token(make_access_token())


def test_validate_access_token_strict_audience_invalid() -> None:
    validator = TokenValidator(
        secrets=TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256"),
        config=TokenValidationConfig(
            audience="service-a",
            require_aud=True,
        ),
    )
    token = make_access_token(aud="service-b")

    with pytest.raises(InvalidToken, match="Invalid access token"):
        validator.validate_access_token(token)


def test_validate_access_token_leeway_allows_near_expiry() -> None:
    validator = TokenValidator(
        secrets=TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256"),
        config=TokenValidationConfig(leeway_seconds=5),
    )
    just_expired = int((datetime.now(timezone.utc) - timedelta(seconds=2)).timestamp())
    token = make_access_token(exp=just_expired)

    payload = validator.validate_access_token(token)

    assert payload.sub == "user-123"


def test_token_validation_config_requires_issuer_when_enforced() -> None:
    with pytest.raises(ValueError, match="issuer must be provided"):
        TokenValidationConfig(require_iss=True)


def test_token_validation_config_requires_audience_when_enforced() -> None:
    with pytest.raises(ValueError, match="audience must be provided"):
        TokenValidationConfig(require_aud=True)


def test_token_validation_config_requires_allowed_algorithms() -> None:
    with pytest.raises(ValueError, match="allowed_algorithms must not be empty"):
        TokenValidationConfig(allowed_algorithms=[])


def test_token_validator_rejects_disallowed_algorithm() -> None:
    with pytest.raises(ValueError, match="not allowed by configuration"):
        TokenValidator(
            secrets=TokenSecret(
                secret_key=SecretStr(VALID_KEY),
                algorithm="HS256",
            ),
            config=TokenValidationConfig(allowed_algorithms=["RS256"]),
        )


def test_token_validator_requires_static_secret_or_key_resolver() -> None:
    with pytest.raises(
        ValueError,
        match="Either secrets or key_resolver must be provided",
    ):
        TokenValidator(secrets=None, config=TokenValidationConfig())


def test_validate_access_token_with_key_resolver_and_kid() -> None:
    resolver = _MapResolver(
        {
            "old-key": TokenSecret(
                secret_key=SecretStr(ROTATED_KEY),
                algorithm="HS256",
            )
        }
    )
    validator = TokenValidator(
        secrets=None,
        config=TokenValidationConfig(),
        key_resolver=resolver,
    )
    token = _encode_access(
        {
            "sub": "user-123",
            "type": "access",
            "email": "test@example.com",
            "role": "user",
            "jti": "test-jti-0000",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "is_active": True,
            "email_verified": False,
            "is_superuser": False,
        },
        secret=ROTATED_KEY,
        headers={"kid": "old-key"},
    )

    payload = validator.validate_access_token(token)

    assert payload.sub == "user-123"
    assert resolver.calls == ["old-key"]


def test_validate_access_token_with_key_resolver_missing_kid() -> None:
    resolver = _MapResolver(
        {
            None: TokenSecret(
                secret_key=SecretStr(VALID_KEY),
                algorithm="HS256",
            )
        }
    )
    validator = TokenValidator(
        secrets=None,
        config=TokenValidationConfig(),
        key_resolver=resolver,
    )

    payload = validator.validate_access_token(make_access_token())

    assert payload.sub == "user-123"
    assert resolver.calls == [None]


def test_validate_access_token_with_key_resolver_unknown_kid() -> None:
    resolver = _MapResolver(
        {
            "current-key": TokenSecret(
                secret_key=SecretStr(VALID_KEY),
                algorithm="HS256",
            )
        }
    )
    validator = TokenValidator(
        secrets=None,
        config=TokenValidationConfig(),
        key_resolver=resolver,
    )
    token = _encode_access(
        {
            "sub": "user-123",
            "type": "access",
            "email": "test@example.com",
            "role": "user",
            "jti": "test-jti-0000",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "is_active": True,
            "email_verified": False,
            "is_superuser": False,
        },
        secret=VALID_KEY,
        headers={"kid": "missing-key"},
    )

    with pytest.raises(InvalidToken, match="Invalid access token"):
        validator.validate_access_token(token)

    assert resolver.calls == ["missing-key"]


def test_validate_access_token_with_key_resolver_invalid_header() -> None:
    resolver = _MapResolver(
        {
            None: TokenSecret(
                secret_key=SecretStr(VALID_KEY),
                algorithm="HS256",
            )
        }
    )
    validator = TokenValidator(
        secrets=None,
        config=TokenValidationConfig(),
        key_resolver=resolver,
    )

    with pytest.raises(InvalidToken, match="Invalid access token"):
        validator.validate_access_token("not-a-jwt")

    assert resolver.calls == []


def test_validate_access_token_with_key_resolver_disallowed_algorithm() -> None:
    resolver = _MapResolver(
        {
            "old-key": TokenSecret(
                secret_key=SecretStr(ROTATED_KEY),
                algorithm="RS256",
            )
        }
    )
    validator = TokenValidator(
        secrets=None,
        config=TokenValidationConfig(allowed_algorithms=["HS256"]),
        key_resolver=resolver,
    )
    token = _encode_access(
        {
            "sub": "user-123",
            "type": "access",
            "email": "test@example.com",
            "role": "user",
            "jti": "test-jti-0000",
            "exp": int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()),
            "is_active": True,
            "email_verified": False,
            "is_superuser": False,
        },
        secret=ROTATED_KEY,
        headers={"kid": "old-key"},
    )

    with pytest.raises(ValueError, match="not allowed by configuration"):
        validator.validate_access_token(token)

    assert resolver.calls == ["old-key"]


def test_token_validation_config_strict_profile() -> None:
    config = TokenValidationConfig.strict(
        issuer="auth.service",
        audience="service-a",
    )

    assert config.require_iss is True
    assert config.require_aud is True
    assert "iat" in config.required_claims
    assert "nbf" in config.required_claims


def test_resolve_secrets_raises_when_both_resolver_and_secrets_are_none() -> None:
    from pydantic import SecretStr

    resolver = _MapResolver(
        {None: TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256")}
    )
    validator = TokenValidator(
        secrets=None,
        config=TokenValidationConfig(),
        key_resolver=resolver,
    )
    # Simulate broken post-init state where both are cleared
    validator._key_resolver = None
    validator._default_secrets = None

    with pytest.raises(RuntimeError, match="key_resolver is None"):
        validator._resolve_secrets("dummy.token.value")


# ---------------------------------------------------------------------------
# 3.6 — Algorithm pinning, malformed-token, and clock skew regression tests
# ---------------------------------------------------------------------------


def _validator_hs256() -> TokenValidator:
    return TokenValidator(
        secrets=TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256"),
        config=TokenValidationConfig(leeway_seconds=0),
    )


def test_alg_none_attack_rejected() -> None:
    """A token with alg=none must never be accepted."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "user-123",
        "type": "access",
        "email": "test@example.com",
        "role": "user",
        "jti": "test-jti-0000",
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "is_active": True,
        "email_verified": False,
        "is_superuser": False,
    }
    # jwt.encode with algorithm="none" produces an unsigned token
    token = jwt.encode(payload, "", algorithm="none")
    with pytest.raises(InvalidToken):
        _validator_hs256().validate_access_token(token)


def test_algorithm_confusion_hs256_token_against_rs256_only_config() -> None:
    """HS256 token presented to an RS256-only validator must be rejected.

    The algorithm allowlist is enforced at validator construction time — a
    secret whose algorithm is not in allowed_algorithms is rejected before any
    token can be decoded. This prevents algorithm-confusion attacks where an
    attacker downgrades the expected algorithm.
    """
    token = make_access_token()  # HS256-signed
    with pytest.raises(ValueError, match="not allowed by configuration"):
        TokenValidator(
            secrets=TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256"),
            config=TokenValidationConfig(allowed_algorithms=["RS256"]),
        ).validate_access_token(token)


def test_missing_sub_raises_invalid_token() -> None:
    """Token without sub claim must be rejected (sub is required by default)."""
    now = datetime.now(timezone.utc)
    payload = {
        "type": "access",
        "email": "test@example.com",
        "role": "user",
        "jti": "test-jti-0000",
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "is_active": True,
        "email_verified": False,
        "is_superuser": False,
    }
    token = jwt.encode(payload, VALID_KEY, algorithm="HS256")
    with pytest.raises(InvalidToken):
        _validator_hs256().validate_access_token(token)


def test_missing_jti_raises_invalid_token() -> None:
    """Token without jti claim must be rejected (jti is required by default)."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "user-123",
        "type": "access",
        "email": "test@example.com",
        "role": "user",
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "is_active": True,
        "email_verified": False,
        "is_superuser": False,
    }
    token = jwt.encode(payload, VALID_KEY, algorithm="HS256")
    with pytest.raises(InvalidToken):
        _validator_hs256().validate_access_token(token)


def test_missing_exp_raises_invalid_token() -> None:
    """Token without exp claim must be rejected (exp is required by default)."""
    payload = {
        "sub": "user-123",
        "type": "access",
        "email": "test@example.com",
        "role": "user",
        "jti": "test-jti-0000",
        "is_active": True,
        "email_verified": False,
        "is_superuser": False,
    }
    token = jwt.encode(payload, VALID_KEY, algorithm="HS256")
    with pytest.raises(InvalidToken):
        _validator_hs256().validate_access_token(token)


def test_future_nbf_raises_invalid_token() -> None:
    """Token with nbf in the future must be rejected (not yet valid)."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": "user-123",
        "type": "access",
        "email": "test@example.com",
        "role": "user",
        "jti": "test-jti-0000",
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "nbf": int((now + timedelta(minutes=5)).timestamp()),  # 5 min in the future
        "is_active": True,
        "email_verified": False,
        "is_superuser": False,
    }
    token = jwt.encode(payload, VALID_KEY, algorithm="HS256")
    with pytest.raises(InvalidToken):
        _validator_hs256().validate_access_token(token)


def test_leeway_allows_token_expired_within_window() -> None:
    """Token expired within leeway_seconds must be accepted (clock skew tolerance)."""
    validator = TokenValidator(
        secrets=TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256"),
        config=TokenValidationConfig(leeway_seconds=30),
    )
    # Expired 10 seconds ago — within the 30 s leeway window
    just_expired = int((datetime.now(timezone.utc) - timedelta(seconds=10)).timestamp())
    token = make_access_token(exp=just_expired)
    payload = validator.validate_access_token(token)
    assert payload.sub == "user-123"


def test_leeway_rejects_token_expired_beyond_window() -> None:
    """Token expired beyond leeway_seconds must be rejected."""
    validator = TokenValidator(
        secrets=TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256"),
        config=TokenValidationConfig(leeway_seconds=5),
    )
    # Expired 60 seconds ago — well outside the 5 s leeway window
    long_expired = int((datetime.now(timezone.utc) - timedelta(seconds=60)).timestamp())
    token = make_access_token(exp=long_expired)
    with pytest.raises(InvalidToken, match="Access token expired"):
        validator.validate_access_token(token)
