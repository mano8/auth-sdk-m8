"""Cross-service JWT contract test (plan 3.5).

Verifies that a token produced with the exact claim structure used by
auth_user_service (TokenAccessData → jwt.encode) is correctly parsed by the
consumer-side TokenValidator into a fully-typed TokenUserData payload.

If any SDK change silently renames a claim (e.g. sub → user_id, or role →
user_role) or changes a type, this test catches it before it reaches
fastapi_service in production.
"""

import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest
from pydantic import SecretStr

from auth_sdk_m8.schemas.auth import TokenAccessData, TokenSecret
from auth_sdk_m8.schemas.user import UserModel
from auth_sdk_m8.security import (
    TokenValidationConfig,
    TokenValidator,
    build_access_validator,
)
from tests.conftest import VALID_KEY, VALID_SETTINGS_KWARGS, IsolatedSettings

_SECRET = TokenSecret(secret_key=SecretStr(VALID_KEY), algorithm="HS256")

_USER_ID = str(uuid.uuid4())
_EMAIL = "contract@example.com"
_FULL_NAME = "Contract User"
_ROLE = "user"


def _issue_token(
    issuer: str | None = None,
    audience: str | None = None,
    expires_delta: timedelta = timedelta(minutes=30),
) -> tuple[str, str]:
    """Replicate auth_user_service.SecurityHelper.create_access_token output."""
    expire = datetime.now(timezone.utc) + expires_delta
    jti = str(uuid.uuid4())
    data = TokenAccessData(
        sub=_USER_ID,
        email=_EMAIL,
        full_name=_FULL_NAME,
        role=_ROLE,
        is_active=True,
        is_superuser=False,
        email_verified=True,
    )
    payload = data.model_dump()
    payload.update({"exp": expire, "jti": jti, "type": "access"})
    if issuer:
        payload["iss"] = issuer
    if audience:
        payload["aud"] = audience
    token = jwt.encode(payload, VALID_KEY, algorithm="HS256")
    return token, jti


def _consumer_validator(
    issuer: str | None = None,
    audience: str | None = None,
) -> TokenValidator:
    """Replicate fastapi_service build_access_validator output."""
    return TokenValidator(
        secrets=_SECRET,
        config=TokenValidationConfig(
            allowed_algorithms=["HS256"],
            issuer=issuer,
            audience=audience,
            require_iss=bool(issuer),
            require_aud=bool(audience),
        ),
    )


class TestJwtCrossServiceContract:
    """Token issued by auth_user_service must be fully parseable by fastapi_service."""

    def test_all_required_claims_present_and_typed(self) -> None:
        token, jti = _issue_token()
        payload = _consumer_validator().validate_access_token(token)

        assert payload.sub == _USER_ID
        assert payload.email == _EMAIL
        assert payload.full_name == _FULL_NAME
        assert payload.role == _ROLE
        assert payload.is_active is True
        assert payload.is_superuser is False
        assert payload.email_verified is True
        assert payload.jti == jti
        assert payload.exp is not None

    def test_sub_is_string_uuid(self) -> None:
        """sub must be a string UUID — fastapi_service constructs UserModel.id from it."""
        token, _ = _issue_token()
        payload = _consumer_validator().validate_access_token(token)
        # Must be parseable as UUID without error
        parsed = uuid.UUID(payload.sub)
        assert str(parsed) == _USER_ID

    def test_payload_constructs_valid_user_model(self) -> None:
        """Consumer converts payload to UserModel — must not raise."""
        token, _ = _issue_token()
        payload = _consumer_validator().validate_access_token(token)
        payload_dict = payload.model_dump(exclude={"exp", "jti", "type", "sub"})
        payload_dict["id"] = payload.sub
        user = UserModel(**payload_dict)
        assert user.email == _EMAIL
        assert user.role == _ROLE

    def test_boundary_claims_enforced_when_configured(self) -> None:
        """Token with matching iss/aud is accepted by a strict consumer."""
        token, _ = _issue_token(
            issuer="https://auth.example.com",
            audience="https://api.example.com",
        )
        validator = _consumer_validator(
            issuer="https://auth.example.com",
            audience="https://api.example.com",
        )
        payload = validator.validate_access_token(token)
        assert payload.sub == _USER_ID

    def test_wrong_issuer_rejected_by_strict_consumer(self) -> None:
        """Token from a different issuer must be rejected by the consumer."""
        from auth_sdk_m8.core.exceptions import InvalidToken

        token, _ = _issue_token(issuer="https://attacker.com")
        validator = _consumer_validator(issuer="https://auth.example.com")
        with pytest.raises(InvalidToken):
            validator.validate_access_token(token)

    def test_expired_token_rejected(self) -> None:
        """An expired token must never be accepted by the consumer."""
        from auth_sdk_m8.core.exceptions import InvalidToken

        token, _ = _issue_token(expires_delta=timedelta(seconds=-60))
        validator = TokenValidator(
            secrets=_SECRET,
            config=TokenValidationConfig(allowed_algorithms=["HS256"], leeway_seconds=0),
        )
        with pytest.raises(InvalidToken, match="expired"):
            validator.validate_access_token(token)

    def test_build_access_validator_factory_accepts_contract_token(self) -> None:
        """build_access_validator (the factory used by both services) accepts the token."""
        settings = IsolatedSettings(**VALID_SETTINGS_KWARGS)
        validator = build_access_validator(settings)
        token, _ = _issue_token()
        payload = validator.validate_access_token(token)
        assert payload.email == _EMAIL
