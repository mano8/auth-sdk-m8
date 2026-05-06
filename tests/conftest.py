"""Shared fixtures and JWT helpers for the auth-sdk-m8 test suite."""

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

from auth_sdk_m8.core.config import CommonSettings

# 46-char key: upper, lower, digit, hyphen, underscore — passes SECRET_KEY_REGEX
VALID_KEY = "Abcdef-1234_XYZ-abcdef-ghijkl-mnopqr-stuvwx"
VALID_PASSWORD = "MyPassw0rd!"

VALID_SETTINGS_KWARGS: dict = {
    "DOMAIN": "localhost",
    "ENVIRONMENT": "local",
    "API_PREFIX": "/api",
    "PROJECT_NAME": "my-project",
    "STACK_NAME": "my-stack",
    "STATIC_BASE_PATH": "/static/path",
    "TEMPLATES_BASE_PATH": "/templates/path",
    "BACKEND_HOST": "http://localhost:8000",
    "FRONTEND_HOST": "http://localhost:3000",
    "BACKEND_CORS_ORIGINS": "http://localhost:3000",
    "SECRET_KEY": VALID_KEY,
    "ACCESS_SECRET_KEY": VALID_KEY,
    "REFRESH_SECRET_KEY": VALID_KEY,
    "DB_HOST": "localhost",
    "DB_PORT": 3306,
    "DB_DATABASE": "testdb",
    "DB_USER": "testuser",
    "DB_PASSWORD": VALID_PASSWORD,
    "REDIS_HOST": "localhost",
    "REDIS_PORT": 6379,
    "REDIS_USER": "redisuser",
    "REDIS_PASSWORD": VALID_PASSWORD,
}


class IsolatedSettings(CommonSettings):
    """CommonSettings subclass that reads ONLY from constructor kwargs."""

    model_config = SettingsConfigDict(env_file=None)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        return (init_settings,)


@pytest.fixture
def valid_settings() -> IsolatedSettings:
    return IsolatedSettings(**VALID_SETTINGS_KWARGS)


@pytest.fixture
def valid_secret() -> SecretStr:
    return SecretStr(VALID_KEY)


def make_access_token(secret: str = VALID_KEY, sub: str = "user-123", **extra) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "type": "access",
        "email": "test@example.com",
        "role": "user",
        "jti": "test-jti-0000",
        "exp": int((now + timedelta(hours=1)).timestamp()),
        "is_active": True,
        "email_verified": False,
        "is_superuser": False,
        **extra,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def make_refresh_token(
    secret: str = VALID_KEY,
    sub: str = "550e8400-e29b-41d4-a716-446655440000",
    **extra,
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": sub,
        "type": "refresh",
        "jti": "test-jti-0000",
        "exp": int((now + timedelta(hours=1)).timestamp()),
        **extra,
    }
    return jwt.encode(payload, secret, algorithm="HS256")
