"""Tests for schemas/user.py, schemas/redis_events.py, schemas/user_events.py."""

import uuid
from datetime import datetime, timezone
from typing import Optional

import pytest
from pydantic import ValidationError

from auth_sdk_m8.authorization import find_inconsistent_privilege_claims_error
from auth_sdk_m8.schemas.base import AuthProviderType, RoleType
from auth_sdk_m8.schemas.redis_events import EventBase
from auth_sdk_m8.schemas.user import SessionModel, UserModel
from auth_sdk_m8.schemas.user_events import SessionRevokedEvent, UserDeletedEvent


def test_user_model() -> None:
    uid = uuid.uuid4()
    user = UserModel(id=uid, email="a@b.com")
    assert user.id == uid
    assert user.role == RoleType.USER
    assert user.is_active is True
    assert user.email_verified is False
    assert user.is_superuser is False
    assert user.full_name is None
    assert user.avatar is None


def test_user_model_normalises_email_case() -> None:
    user = UserModel(id=uuid.uuid4(), email="User@Example.COM")
    assert user.email == "user@example.com"


def test_user_model_normalises_email_whitespace() -> None:
    user = UserModel(id=uuid.uuid4(), email="  user@example.com  ")
    assert user.email == "user@example.com"


def test_user_model_with_all_fields() -> None:
    uid = uuid.uuid4()
    user = UserModel(
        id=uid,
        email="admin@b.com",
        full_name="Admin User",
        avatar="http://cdn/img.png",
        is_active=False,
        email_verified=True,
        # is_superuser=True is only valid on the canonical SUPERADMIN pair (§3.1).
        is_superuser=True,
        role=RoleType.SUPERADMIN,
    )
    assert user.is_superuser is True
    assert user.role == RoleType.SUPERADMIN


def test_user_model_tenant_id_defaults_none() -> None:
    user = UserModel(id=uuid.uuid4(), email="a@b.com")
    assert user.tenant_id is None


def test_user_model_tenant_id_coerced_from_string() -> None:
    tenant = uuid.uuid4()
    user = UserModel.model_validate(
        {"id": uuid.uuid4(), "email": "a@b.com", "tenant_id": str(tenant)}
    )
    assert isinstance(user.tenant_id, uuid.UUID)
    assert user.tenant_id == tenant


# ── Canonical role/flag invariant (§3.1) ─────────────────────────────────────


@pytest.mark.parametrize("role", list(RoleType))
def test_user_model_accepts_canonical_pairs(role: RoleType) -> None:
    is_superuser = role == RoleType.SUPERADMIN
    user = UserModel(
        id=uuid.uuid4(), email="a@b.com", role=role, is_superuser=is_superuser
    )
    assert user.role is role
    assert user.is_superuser is is_superuser


@pytest.mark.parametrize("role", list(RoleType))
def test_user_model_rejects_inconsistent_pairs(role: RoleType) -> None:
    with pytest.raises(ValidationError) as exc_info:
        UserModel(
            id=uuid.uuid4(),
            email="a@b.com",
            role=role,
            is_superuser=role != RoleType.SUPERADMIN,
        )

    assert find_inconsistent_privilege_claims_error(exc_info.value) is not None


def test_user_model_flag_alone_cannot_claim_superuser() -> None:
    # A consumer building UserModel from token claims must never see this pair.
    with pytest.raises(ValidationError):
        UserModel(
            id=uuid.uuid4(), email="a@b.com", role=RoleType.ADMIN, is_superuser=True
        )


def test_user_model_error_carries_only_the_bounded_reason() -> None:
    with pytest.raises(ValidationError) as exc_info:
        UserModel(
            id=uuid.uuid4(), email="a@b.com", role=RoleType.USER, is_superuser=True
        )

    found = find_inconsistent_privilege_claims_error(exc_info.value)
    assert str(found) == "inconsistent_privilege_claims"


def test_session_model() -> None:
    now = datetime.now(timezone.utc)
    sid = uuid.uuid4()
    session = SessionModel(
        id=sid,
        provider=AuthProviderType.PASSWORD,
        jwt_jti="a" * 16,
        refresh_token_hash="b" * 64,
        jwt_expires_at=now,
        refresh_expires_at=now,
    )
    assert session.provider == AuthProviderType.PASSWORD
    assert session.external_access_token is None
    assert session.external_refresh_token is None
    assert session.external_token_expires_at is None


def test_session_model_with_external_tokens() -> None:
    now = datetime.now(timezone.utc)
    session = SessionModel(
        id=uuid.uuid4(),
        provider=AuthProviderType.GOOGLE,
        jwt_jti="j" * 16,
        refresh_token_hash="r" * 64,
        jwt_expires_at=now,
        refresh_expires_at=now,
        external_access_token="ext-access",
        external_refresh_token="ext-refresh",
        external_token_expires_at=now,
    )
    assert session.external_access_token == "ext-access"
    assert session.external_token_expires_at == now


def test_event_base() -> None:
    event = EventBase(event_type="some.event")
    assert event.event_type == "some.event"
    assert event.version == "v1"


def test_event_base_custom_version() -> None:
    event = EventBase(event_type="x", version="v2")
    assert event.version == "v2"


def test_user_deleted_event_defaults() -> None:
    event = UserDeletedEvent(user_id="user-123")
    assert event.event_type == "user.deleted"
    assert event.version == "v1"
    assert event.user_id == "user-123"


def test_user_deleted_event_inherits_event_base() -> None:
    assert issubclass(UserDeletedEvent, EventBase)


def test_session_revoked_event_v1_shape_has_no_v2_fields() -> None:
    # Today's shape: {user_id, jti}. Constructing it exactly as fa-auth-m8's
    # current callers do must keep working — the v2 fields are additive.
    event = SessionRevokedEvent(user_id="user-123", jti="jti-abc")

    assert event.event_type == "session.revoked"
    assert event.version == "v1"
    assert event.user_id == "user-123"
    assert event.jti == "jti-abc"
    assert event.auth_generation is None
    assert event.event_id is None


def test_session_revoked_event_jti_none_means_all_sessions() -> None:
    event = SessionRevokedEvent(user_id="user-123", jti=None)
    assert event.jti is None


def test_session_revoked_event_v2_shape() -> None:
    event = SessionRevokedEvent(
        user_id="user-123",
        jti="jti-abc",
        version="v2",
        auth_generation=7,
        event_id="user-123:7:publish:user-wide",
    )

    assert event.version == "v2"
    assert event.auth_generation == 7
    assert event.event_id == "user-123:7:publish:user-wide"


def test_session_revoked_event_inherits_event_base() -> None:
    assert issubclass(SessionRevokedEvent, EventBase)


@pytest.mark.parametrize("generation", [0, -1])
def test_session_revoked_event_rejects_a_non_positive_generation(
    generation: int,
) -> None:
    with pytest.raises(ValidationError):
        SessionRevokedEvent(user_id="user-123", auth_generation=generation)


def test_session_revoked_event_rejects_an_empty_event_id() -> None:
    with pytest.raises(ValidationError):
        SessionRevokedEvent(user_id="user-123", event_id="")


def test_session_revoked_event_old_consumer_ignores_v2_fields() -> None:
    # A not-yet-upgraded consumer parsing model that only knows the v1 shape
    # must be able to read a v2 payload safely, ignoring unknown fields.
    class _LegacySessionRevokedEvent(EventBase):
        event_type: str = "session.revoked"
        user_id: str
        jti: Optional[str] = None

    v2_payload = SessionRevokedEvent(
        user_id="user-123",
        jti="jti-abc",
        version="v2",
        auth_generation=7,
        event_id="user-123:7:publish:user-wide",
    ).model_dump()

    legacy = _LegacySessionRevokedEvent.model_validate(v2_payload)
    assert legacy.user_id == "user-123"
    assert legacy.jti == "jti-abc"
