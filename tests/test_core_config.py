"""Tests for auth_sdk_m8.core.config."""

import sys
from unittest.mock import MagicMock, patch

import pytest

from auth_sdk_m8.core.config import (
    EnvProvider,
    SecretProvider,
    VaultProvider,
    parse_cors,
    settings_customise_sources,
)
from tests.conftest import VALID_SETTINGS_KWARGS, IsolatedSettings

# ── SecretProvider ────────────────────────────────────────────────────────────


def test_secret_provider_get_raises() -> None:
    provider = SecretProvider()
    with pytest.raises(NotImplementedError):
        provider.get("KEY")


# ── EnvProvider ───────────────────────────────────────────────────────────────


def test_env_provider_get_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_MY_SECRET", "mysecretvalue")
    assert EnvProvider().get("TEST_MY_SECRET") == "mysecretvalue"


def test_env_provider_get_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TEST_MY_SECRET", raising=False)
    assert EnvProvider().get("TEST_MY_SECRET") is None


# ── VaultProvider ─────────────────────────────────────────────────────────────


def test_vault_provider_no_hvac() -> None:
    with patch.dict(sys.modules, {"hvac": None}):
        with pytest.raises(RuntimeError, match="hvac library"):
            VaultProvider("http://vault:8200", "token")


def test_vault_provider_get() -> None:
    mock_hvac = MagicMock()
    mock_client = MagicMock()
    mock_hvac.Client.return_value = mock_client
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"SECRET_KEY": "my-secret"}}
    }
    with patch.dict(sys.modules, {"hvac": mock_hvac}):
        provider = VaultProvider("http://vault:8200", "token")
        assert provider.get("SECRET_KEY") == "my-secret"


def test_vault_provider_get_missing_key() -> None:
    mock_hvac = MagicMock()
    mock_client = MagicMock()
    mock_hvac.Client.return_value = mock_client
    mock_client.secrets.kv.v2.read_secret_version.return_value = {"data": {"data": {}}}
    with patch.dict(sys.modules, {"hvac": mock_hvac}):
        provider = VaultProvider("http://vault:8200", "token")
        assert provider.get("MISSING") is None


# ── settings_customise_sources ────────────────────────────────────────────────


def test_settings_customise_sources_local(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "local")
    monkeypatch.delenv("SECRET_PROVIDER", raising=False)
    init = MagicMock()
    env = MagicMock()
    file_sec = MagicMock()
    sources = settings_customise_sources(init, env, file_sec)
    assert len(sources) == 3


def test_settings_customise_sources_vault_from_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SECRET_PROVIDER", "vault")
    monkeypatch.setenv("VAULT_ADDR", "http://vault:8200")
    monkeypatch.setenv("VAULT_TOKEN", "mytoken")

    mock_hvac = MagicMock()
    mock_client = MagicMock()
    mock_hvac.Client.return_value = mock_client
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"ACCESS_SECRET_KEY": "val"}}
    }

    with patch.dict(sys.modules, {"hvac": mock_hvac}):
        sources = settings_customise_sources(MagicMock(), MagicMock(), MagicMock())

    assert len(sources) == 4
    vault_source = sources[3]
    result = vault_source(MagicMock())
    assert "ACCESS_SECRET_KEY" in result


def test_settings_customise_sources_vault_from_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "staging")
    monkeypatch.setenv("SECRET_PROVIDER", "vault")
    monkeypatch.setenv("VAULT_ADDR", "http://vault:8200")
    monkeypatch.delenv("VAULT_TOKEN", raising=False)

    mock_hvac = MagicMock()
    mock_hvac.Client.return_value = MagicMock()

    with (
        patch.dict(sys.modules, {"hvac": mock_hvac}),
        patch("auth_sdk_m8.core.config.Path") as mock_path_cls,
    ):
        mock_path_instance = MagicMock()
        mock_path_instance.is_file.return_value = True
        mock_path_instance.read_text.return_value = "file-token"
        mock_path_cls.return_value = mock_path_instance

        sources = settings_customise_sources(
            MagicMock(),
            MagicMock(),
            MagicMock(),
        )

    assert len(sources) == 4


def test_settings_customise_sources_vault_no_addr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SECRET_PROVIDER", "vault")
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)

    with patch("auth_sdk_m8.core.config.Path") as mock_path_cls:
        mock_path_cls.return_value.is_file.return_value = False
        sources = settings_customise_sources(MagicMock(), MagicMock(), MagicMock())

    assert len(sources) == 3


# ── parse_cors ────────────────────────────────────────────────────────────────


def test_parse_cors_single_valid() -> None:
    result = parse_cors("http://localhost:3000")
    assert result == ["http://localhost:3000"]


def test_parse_cors_multiple_valid() -> None:
    result = parse_cors("http://localhost:3000,https://example.com")
    assert len(result) == 2
    assert "https://example.com" in result


def test_parse_cors_strips_trailing_slash() -> None:
    result = parse_cors("http://localhost:3000/")
    assert result == ["http://localhost:3000"]


def test_parse_cors_invalid_origin() -> None:
    with pytest.raises(ValueError, match="Invalid host"):
        parse_cors("not-a-url")


def test_parse_cors_empty_string() -> None:
    with pytest.raises(ValueError, match="at least one valid origin"):
        parse_cors("   ,   ")


# ── CommonSettings ────────────────────────────────────────────────────────────


def test_common_settings_valid(valid_settings: IsolatedSettings) -> None:
    assert valid_settings.DOMAIN == "localhost"
    assert valid_settings.ENVIRONMENT == "local"


def test_common_settings_allowed_origins_includes_frontend() -> None:
    kwargs = {**VALID_SETTINGS_KWARGS, "BACKEND_CORS_ORIGINS": "http://other.com"}
    s = IsolatedSettings(**kwargs)
    assert "http://localhost:3000" in s.ALLOWED_ORIGINS


def test_common_settings_allowed_origins_frontend_already_included() -> None:
    s = IsolatedSettings(**VALID_SETTINGS_KWARGS)
    # frontend IS in BACKEND_CORS_ORIGINS — should not be duplicated
    origins = s.ALLOWED_ORIGINS
    assert origins.count("http://localhost:3000") == 1


def test_common_settings_emails_enabled_true() -> None:
    s = IsolatedSettings(
        **VALID_SETTINGS_KWARGS,
        SMTP_HOST="smtp.example.com",
        EMAILS_FROM_EMAIL="noreply@example.com",
    )
    assert s.emails_enabled is True


def test_common_settings_emails_enabled_false_no_smtp() -> None:
    s = IsolatedSettings(**VALID_SETTINGS_KWARGS)
    assert s.emails_enabled is False


def test_common_settings_emails_enabled_false_no_email() -> None:
    s = IsolatedSettings(**VALID_SETTINGS_KWARGS, SMTP_HOST="smtp.example.com")
    assert s.emails_enabled is False


def test_common_settings_invalid_password() -> None:
    kwargs = {**VALID_SETTINGS_KWARGS, "DB_PASSWORD": "weakpass"}
    with pytest.raises(Exception, match="strong password"):
        IsolatedSettings(**kwargs)


def test_common_settings_invalid_secret_key() -> None:
    kwargs = {**VALID_SETTINGS_KWARGS, "ACCESS_SECRET_KEY": "tooshortkey"}
    with pytest.raises(Exception, match="secret key"):
        IsolatedSettings(**kwargs)


def test_common_settings_empty_required_field() -> None:
    kwargs = {**VALID_SETTINGS_KWARGS, "PROJECT_NAME": "valid-name"}
    kwargs["DOMAIN"] = ""
    with pytest.raises(Exception):
        IsolatedSettings(**kwargs)


def test_common_settings_insecure_default_secret() -> None:
    kwargs = {**VALID_SETTINGS_KWARGS, "DB_PASSWORD": "changethis"}
    with pytest.raises(Exception, match="Insecure default|strong password"):
        IsolatedSettings(**kwargs)


def test_common_settings_sqlalchemy_uri_mysql(valid_settings: IsolatedSettings) -> None:
    uri = valid_settings.SQLALCHEMY_DATABASE_URI
    assert "mysql+pymysql" in uri
    assert "testuser" in uri
    assert "testdb" in uri


def test_common_settings_sqlalchemy_uri_postgres() -> None:
    kwargs = {**VALID_SETTINGS_KWARGS, "SELECTED_DB": "Postgres", "DB_PORT": 5432}
    s = IsolatedSettings(**kwargs)
    uri = s.SQLALCHEMY_DATABASE_URI
    assert "postgresql+psycopg2" in uri
    assert "testuser" in uri
    assert "testdb" in uri


def test_common_settings_validate_password_invalid() -> None:
    from pydantic import SecretStr as _SecretStr

    with pytest.raises(ValueError, match="at least 8 characters"):
        IsolatedSettings._validate_password("DB_PASSWORD", _SecretStr("weak"))


def test_common_settings_cors_origins_not_string() -> None:
    kwargs = {**VALID_SETTINGS_KWARGS, "BACKEND_CORS_ORIGINS": 123}
    with pytest.raises(Exception, match="comma-separated string"):
        IsolatedSettings(**kwargs)
