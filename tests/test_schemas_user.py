"""Tests for schemas/user.py, schemas/redis_events.py, schemas/user_events.py."""
import uuid
from datetime import datetime, timezone

from auth_sdk_m8.schemas.base import AuthProviderType, RoleType
from auth_sdk_m8.schemas.redis_events import EventBase
from auth_sdk_m8.schemas.user import SessionModel, UserModel
from auth_sdk_m8.schemas.user_events import UserDeletedEvent


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


def test_user_model_with_all_fields() -> None:
    uid = uuid.uuid4()
    user = UserModel(
        id=uid,
        email="admin@b.com",
        full_name="Admin User",
        avatar="http://cdn/img.png",
        is_active=False,
        email_verified=True,
        is_superuser=True,
        role=RoleType.ADMIN,
    )
    assert user.is_superuser is True
    assert user.role == RoleType.ADMIN


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
