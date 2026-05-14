"""Shared fixtures and JWT helpers for the auth-sdk-m8 test suite."""

from datetime import datetime, timedelta, timezone

import jwt
import pytest
from pydantic import SecretStr
from pydantic_settings import SettingsConfigDict

from auth_sdk_m8.core.config import CommonSettings

# 46-char key: upper, lower, digit, hyphen, underscore — passes SECRET_KEY_REGEX
VALID_KEY = "Abcdef-1234_XYZ-abcdef-ghijkl-mnopqr-stuvwx"
# Different 46-char key used to produce tokens with an invalid signature
WRONG_KEY = "Zyxwvu-9876_ABC-zyxwvu-tsrqpo-nmlkji-hgfedc"

# 2048-bit RSA keypair generated for tests only — never use in production.
RSA_PRIVATE_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzWCXqrK+FlZPOYIieExjEQCqHeIQrEDiAJN6zIWAULZlV2BS
SUHlIhQqZQ0zSoORT30G6AHXCC+bjCz06piAhA/nMiD1szbymxThnumDVcS3/tdl
BIMmRyfdWzUCxgMdV1OsVtQAC0lVThwKfyDdoCeyRFUYa9tfwIjMSvuU0PFXAtvU
EDwJlLmH4a8lkTcfAB5DD0eWzK2Q6KLT34VLMT8PQxtNfucWvuGnyhBHe4Ze2cvG
hINTLL4nUGi0YqwWAnxkzb3NnWJ5PV/X08QKZtJUy2pbhysV/Th9gu8sxnKN2mNz
TgSeGVaE+Yk5hpi+UTqfWQCK594KTowJa0LTMwIDAQABAoIBACBlL5c/2YcJdzax
hcFm/ytj6PGMwqeBFoUTvkd7eWmB08tsCJ7Ak6WD+8nzwpbq2OVqacf33lTOuaDr
SHimtILgRU4db9QkgzEeIpaf69UAEivTCv6it0t7CMoFuxnDzQGE08bgat9c4mVP
PAKgiwTjrhVkPNVqhZiHm33qYCdy2blTOBotgnG5tMUpKmT5BtXAq3/f8qadH5SB
CNqL0lwlfBB5CzTO/RIFNDA4IwwbpVYrIWKq83q0DlyDRl4/4qLY/0osZW506NJf
A8QUOgQGiW6X7IaPSZ5OaL1c8EnmhrGanZnYjh7dMsDJFAoY2yQ6a7iJqPMAivVd
tA2jDOECgYEA5x8NRDsMt9C/DbixP3YAsVBkCBUQAHuumC4YNphKN7M/SE0oDc57
7dkJghLJbrQ5ssuFodUKVIXM1UCZk7EgAUKrKCNli01/bhIxgPcKbSxLGjKRWAUW
UxhK00tLRrR1QiEoR077huLewHuG+mw4FL1I2MEP+/tYEaPwf0hIaKECgYEA43we
3JE0Tm3OwY8CcRRhMEn++DZFioobm0pIT80p5GEKjolbQQex+dulpd9i/0GLER+C
vW+ickW62Z6L7tez2u51GSyQEAUEKKsUbruKjCW/8KKx7s4/f/qiLrYkzhcSGGvZ
A4t7WoLxt0sV2gk0yWXYJWRVgomtXBv/tnsch1MCgYBVmqi9RunVA5pgKLJuAPUM
t+v1GmgM5cKrVxdc0Vdb/iZIT1uwkXRRinv9E5xMRrDASqW6ZUAoQk62BfFcRNTH
4rumaEXqLNAwIsj3LYlNGoTOtUAkS+4S5QKB9HdzPs/XqJRUpSqAsXMz9AzwoDi9
ZcafkhKrkFL0ZbZkTo+TQQKBgQDE8jm51hDF8fV1yD1h7zXxW67d8Aam2cjq2hXe
2Q3yxj0giDS0CViBrDMud0c7HOCsc256WYL3kf0h2Uzm/GKfIaHJqLYU2HLwTqVC
9SUPDsOtLv4DdRau0yvEazdUIc8ty3k3w3OJOiLRALWrbhsAXicSwFnzyQSI4Uiz
EMTzNwKBgQDkKBaMUOr2M5uhRltCZTiZIFJTlFUB4NEt0JurqwlMgGrHsQIH7b+w
CfXhpg/P/cn2UjoHonHYWAw/5AWv7NJAMiSoPFM41ypgqdWecwSDzm2aPOpQE4oZ
an056qoZgrQRdeX5bYMCU+t+DJFFJCItpFkQ2jGGEFe6oslrZvgNMw==
-----END RSA PRIVATE KEY-----"""

RSA_PUBLIC_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzWCXqrK+FlZPOYIieExj
EQCqHeIQrEDiAJN6zIWAULZlV2BSSUHlIhQqZQ0zSoORT30G6AHXCC+bjCz06piA
hA/nMiD1szbymxThnumDVcS3/tdlBIMmRyfdWzUCxgMdV1OsVtQAC0lVThwKfyDd
oCeyRFUYa9tfwIjMSvuU0PFXAtvUEDwJlLmH4a8lkTcfAB5DD0eWzK2Q6KLT34VL
MT8PQxtNfucWvuGnyhBHe4Ze2cvGhINTLL4nUGi0YqwWAnxkzb3NnWJ5PV/X08QK
ZtJUy2pbhysV/Th9gu8sxnKN2mNzTgSeGVaE+Yk5hpi+UTqfWQCK594KTowJa0LT
MwIDAQAB
-----END PUBLIC KEY-----"""
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
