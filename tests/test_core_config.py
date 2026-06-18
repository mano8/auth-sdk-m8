"""Tests for auth_sdk_m8.core.config."""

import sys
from pathlib import Path
from typing import ClassVar, Optional
from unittest.mock import MagicMock, patch

import pytest
from pydantic_settings import SettingsConfigDict

from auth_sdk_m8.core.config import (
    CommonSettings,
    EnvProvider,
    SecretProvider,
    VaultProvider,
    _build_file_secret_source,
    _build_vault_source,
    _read_secret_file,
    check_config_health,
    parse_cors,
    settings_customise_sources,
)
from auth_sdk_m8.core.exceptions import ConfigurationError
from tests.conftest import (
    PROD_VALID_KEY,
    RSA_PRIVATE_PEM,
    RSA_PUBLIC_PEM,
    VALID_PASSWORD,
    VALID_SETTINGS_KWARGS,
    IsolatedSettings,
)

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


# ── _guard_production_placeholder_keys ───────────────────────────────────────


def test_guard_blocks_known_dev_key_in_production() -> None:
    """VALID_KEY (a known dev placeholder) is rejected in production."""
    kwargs = {
        **VALID_SETTINGS_KWARGS,
        "ENVIRONMENT": "production",
        # Use prod-safe key everywhere *except* the one we want to test.
        "ACCESS_SECRET_KEY": PROD_VALID_KEY,
        "REFRESH_SECRET_KEY": PROD_VALID_KEY,
        # Deliberately leave EVENT_SIGNING_KEY as VALID_KEY (a known dev key).
        "EVENT_SIGNING_KEY": VALID_SETTINGS_KWARGS["EVENT_SIGNING_KEY"],
    }
    with pytest.raises(Exception, match="well-known development key"):
        IsolatedSettings(**kwargs)


def test_guard_blocks_known_dev_key_in_strict_mode() -> None:
    """STRICT_PRODUCTION_MODE triggers the guard even with ENVIRONMENT!=production."""
    from tests.conftest import VALID_KEY

    kwargs = {
        **VALID_SETTINGS_KWARGS,
        "ENVIRONMENT": "local",
        "STRICT_PRODUCTION_MODE": True,
        "ACCESS_SECRET_KEY": VALID_KEY,  # dev placeholder
        "REFRESH_SECRET_KEY": PROD_VALID_KEY,
        "EVENT_SIGNING_KEY": PROD_VALID_KEY,
    }
    with pytest.raises(Exception, match="well-known development key"):
        IsolatedSettings(**kwargs)


def test_guard_allows_prod_safe_key_in_production() -> None:
    """A key not in _dev_placeholder_keys is accepted in production."""
    kwargs = {
        **VALID_SETTINGS_KWARGS,
        "ENVIRONMENT": "production",
        "ACCESS_SECRET_KEY": PROD_VALID_KEY,
        "REFRESH_SECRET_KEY": PROD_VALID_KEY,
        "EVENT_SIGNING_KEY": PROD_VALID_KEY,
    }
    s = IsolatedSettings(**kwargs)
    assert s.ENVIRONMENT == "production"


def test_guard_skips_none_fields_in_production() -> None:
    """None signing fields in production are skipped (not raised)."""
    kwargs = {
        **VALID_SETTINGS_KWARGS,
        "ENVIRONMENT": "production",
        "ACCESS_SECRET_KEY": PROD_VALID_KEY,
        "REFRESH_SECRET_KEY": PROD_VALID_KEY,
        "EVENT_SIGNING_KEY": PROD_VALID_KEY,
        # Null out the optional key — guard must not crash on None.
        "EVENT_SIGNING_ENABLED": False,
        # Override to None after disabling (validator allows None when disabled)
    }
    kwargs["EVENT_SIGNING_KEY"] = None
    s = IsolatedSettings(**kwargs)
    assert s.ENVIRONMENT == "production"


def test_guard_skips_in_non_production() -> None:
    """Known dev keys are accepted in local/development environments."""
    from tests.conftest import VALID_KEY

    kwargs = {**VALID_SETTINGS_KWARGS, "ENVIRONMENT": "local"}
    s = IsolatedSettings(**kwargs)
    assert s.ACCESS_SECRET_KEY is not None
    assert s.ACCESS_SECRET_KEY.get_secret_value() == VALID_KEY


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


# ── TOKEN_MODE computed flags ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("stateless", True),
        ("stateful", False),
        ("hybrid", False),
    ],
)
def test_is_stateless(mode: str, expected: bool) -> None:
    s = IsolatedSettings(**{**VALID_SETTINGS_KWARGS, "TOKEN_MODE": mode})
    assert s.is_stateless is expected


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("stateful", True),
        ("stateless", False),
        ("hybrid", False),
    ],
)
def test_is_stateful(mode: str, expected: bool) -> None:
    s = IsolatedSettings(**{**VALID_SETTINGS_KWARGS, "TOKEN_MODE": mode})
    assert s.is_stateful is expected


@pytest.mark.parametrize(
    "mode,expected",
    [
        ("stateful", True),
        ("hybrid", True),
        ("stateless", False),
    ],
)
def test_requires_redis(mode: str, expected: bool) -> None:
    s = IsolatedSettings(**{**VALID_SETTINGS_KWARGS, "TOKEN_MODE": mode})
    assert s.requires_redis is expected


def test_flags_are_mutually_consistent_for_all_modes() -> None:
    """is_stateless and requires_redis must never both be True."""
    for mode in ("stateless", "stateful", "hybrid"):
        s = IsolatedSettings(**{**VALID_SETTINGS_KWARGS, "TOKEN_MODE": mode})
        assert not (s.is_stateless and s.requires_redis), (
            f"TOKEN_MODE={mode}: is_stateless and requires_redis cannot both be True"
        )


# ── effective_failure_mode ────────────────────────────────────────────────────


def test_effective_failure_mode_defaults() -> None:
    """Default policy: refresh+session+access_revocation fail_closed, rate_limit fail_open."""
    s = IsolatedSettings(**VALID_SETTINGS_KWARGS)
    assert s.effective_failure_mode("refresh_validation") == "fail_closed"
    assert s.effective_failure_mode("session_write") == "fail_closed"
    assert s.effective_failure_mode("rate_limit") == "fail_open"
    assert s.effective_failure_mode("access_revocation") == "fail_closed"


def test_effective_failure_mode_strict_overrides_all() -> None:
    """AUTH_STRICT_MODE=True forces all controls to fail_closed."""
    s = IsolatedSettings(**{**VALID_SETTINGS_KWARGS, "AUTH_STRICT_MODE": True})
    for control in (
        "refresh_validation",
        "session_write",
        "rate_limit",
        "access_revocation",
    ):
        assert s.effective_failure_mode(control) == "fail_closed"  # type: ignore[arg-type]


def test_effective_failure_mode_per_control_override() -> None:
    """Individual control modes can be overridden independently."""
    s = IsolatedSettings(
        **{
            **VALID_SETTINGS_KWARGS,
            "RATE_LIMIT_FAILURE_MODE": "fail_closed",
            "ACCESS_REVOCATION_FAILURE_MODE": "fail_closed",
        }
    )
    assert s.effective_failure_mode("rate_limit") == "fail_closed"
    assert s.effective_failure_mode("access_revocation") == "fail_closed"
    assert s.effective_failure_mode("refresh_validation") == "fail_closed"
    assert s.effective_failure_mode("session_write") == "fail_closed"


# ── REDIS_SSL ──────────────────────────────────────────────────────────────────


def test_redis_ssl_defaults_to_false() -> None:
    s = IsolatedSettings(**VALID_SETTINGS_KWARGS)
    assert s.REDIS_SSL is False


def test_redis_ssl_can_be_enabled(tmp_path) -> None:
    ca = tmp_path / "ca.crt"
    ca.write_text("CA")
    s = IsolatedSettings(
        **{**VALID_SETTINGS_KWARGS, "REDIS_SSL": True, "REDIS_SSL_CA": str(ca)}
    )
    assert s.REDIS_SSL is True


# ── _validate_redis_ssl ────────────────────────────────────────────────────────


def test_redis_ssl_ca_required_when_ssl_enabled() -> None:
    """REDIS_SSL=true without REDIS_SSL_CA must raise."""
    with pytest.raises(Exception, match="REDIS_SSL_CA is required"):
        IsolatedSettings(**{**VALID_SETTINGS_KWARGS, "REDIS_SSL": True})


def test_redis_ssl_ca_file_not_found_raises(tmp_path) -> None:
    """REDIS_SSL_CA pointing to a missing file must raise."""
    with pytest.raises(Exception, match="REDIS_SSL_CA file not found"):
        IsolatedSettings(
            **{
                **VALID_SETTINGS_KWARGS,
                "REDIS_SSL_CA": str(tmp_path / "missing_ca.crt"),
            }
        )


def test_redis_ssl_cert_file_not_found_raises(tmp_path) -> None:
    """REDIS_SSL_CERT pointing to a missing file must raise."""
    ca = tmp_path / "ca.crt"
    ca.write_text("CA")
    with pytest.raises(Exception, match="REDIS_SSL_CERT file not found"):
        IsolatedSettings(
            **{
                **VALID_SETTINGS_KWARGS,
                "REDIS_SSL": True,
                "REDIS_SSL_CA": str(ca),
                "REDIS_SSL_CERT": str(tmp_path / "missing.crt"),
            }
        )


def test_redis_ssl_key_file_not_found_raises(tmp_path) -> None:
    """REDIS_SSL_KEY pointing to a missing file must raise."""
    ca = tmp_path / "ca.crt"
    cert = tmp_path / "client.crt"
    ca.write_text("CA")
    cert.write_text("CERT")
    with pytest.raises(Exception, match="REDIS_SSL_KEY file not found"):
        IsolatedSettings(
            **{
                **VALID_SETTINGS_KWARGS,
                "REDIS_SSL": True,
                "REDIS_SSL_CA": str(ca),
                "REDIS_SSL_CERT": str(cert),
                "REDIS_SSL_KEY": str(tmp_path / "missing.key"),
            }
        )


def test_redis_ssl_cert_without_key_raises(tmp_path) -> None:
    """REDIS_SSL_CERT without REDIS_SSL_KEY must raise (XOR rule)."""
    ca = tmp_path / "ca.crt"
    cert = tmp_path / "client.crt"
    ca.write_text("CA")
    cert.write_text("CERT")
    with pytest.raises(Exception, match="must both be set or both unset"):
        IsolatedSettings(
            **{
                **VALID_SETTINGS_KWARGS,
                "REDIS_SSL": True,
                "REDIS_SSL_CA": str(ca),
                "REDIS_SSL_CERT": str(cert),
            }
        )


def test_redis_ssl_key_without_cert_raises(tmp_path) -> None:
    """REDIS_SSL_KEY without REDIS_SSL_CERT must raise (XOR rule)."""
    ca = tmp_path / "ca.crt"
    key = tmp_path / "client.key"
    ca.write_text("CA")
    key.write_text("KEY")
    with pytest.raises(Exception, match="must both be set or both unset"):
        IsolatedSettings(
            **{
                **VALID_SETTINGS_KWARGS,
                "REDIS_SSL": True,
                "REDIS_SSL_CA": str(ca),
                "REDIS_SSL_KEY": str(key),
            }
        )


def test_redis_ssl_tls_only_passes(tmp_path) -> None:
    """REDIS_SSL=true with only CA (no client cert) is valid."""
    ca = tmp_path / "ca.crt"
    ca.write_text("CA")
    s = IsolatedSettings(
        **{
            **VALID_SETTINGS_KWARGS,
            "REDIS_SSL": True,
            "REDIS_SSL_CA": str(ca),
        }
    )
    assert s.REDIS_SSL is True
    assert s.REDIS_SSL_CERT is None
    assert s.REDIS_SSL_KEY is None


def test_redis_ssl_mtls_passes(tmp_path) -> None:
    """REDIS_SSL=true with CA + client cert + key (mTLS) is valid."""
    ca = tmp_path / "ca.crt"
    cert = tmp_path / "client.crt"
    key = tmp_path / "client.key"
    ca.write_text("CA")
    cert.write_text("CERT")
    key.write_text("KEY")
    s = IsolatedSettings(
        **{
            **VALID_SETTINGS_KWARGS,
            "REDIS_SSL": True,
            "REDIS_SSL_CA": str(ca),
            "REDIS_SSL_CERT": str(cert),
            "REDIS_SSL_KEY": str(key),
        }
    )
    assert s.REDIS_SSL_CA == str(ca)
    assert s.REDIS_SSL_CERT == str(cert)
    assert s.REDIS_SSL_KEY == str(key)


def test_redis_ssl_false_fields_default_none() -> None:
    """With REDIS_SSL=false (default), all SSL path fields default to None."""
    s = IsolatedSettings(**VALID_SETTINGS_KWARGS)
    assert s.REDIS_SSL_CA is None
    assert s.REDIS_SSL_CERT is None
    assert s.REDIS_SSL_KEY is None


# ── check_config_health ────────────────────────────────────────────────────────────
class DummySettings:
    """Minimal settings object for testing."""

    ACCESS_TOKEN_ALGORITHM: str
    TOKEN_MODE: str

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    @property
    def requires_redis(self) -> bool:
        return getattr(self, "TOKEN_MODE", "stateful") in {"stateful", "hybrid"}

    @property
    def is_stateless(self) -> bool:
        return getattr(self, "TOKEN_MODE", "stateful") == "stateless"


class DummyLogger:
    """Logger spy for capturing logs."""

    def __init__(self) -> None:
        self.warnings: list[str] = []
        self.criticals: list[str] = []

    def warning(self, msg: str, *args: object) -> None:
        self.warnings.append(msg % args if args else msg)

    def critical(self, msg: str, *args: object) -> None:
        self.criticals.append(msg % args if args else msg)


def test_valid_config_no_logs() -> None:
    """Should produce no warnings or errors for valid config."""
    settings = DummySettings(
        ACCESS_TOKEN_ALGORITHM="HS256",
        TOKEN_MODE="stateful",
        REDIS_HOST="localhost",
        REDIS_PASSWORD="pass",
        JWKS_CACHE_TTL_SECONDS=300,
    )

    logger = DummyLogger()

    check_config_health(settings, logger)

    assert logger.warnings == []
    assert logger.criticals == []


def test_missing_keys_fatal_error() -> None:
    """Should raise when asymmetric algo has no public key source or JWKS."""
    settings = DummySettings(
        ACCESS_TOKEN_ALGORITHM="RS256",
        JWKS_URI=None,
        TOKEN_MODE="stateful",
        REDIS_HOST="localhost",
        REDIS_PASSWORD="pass",
    )

    logger = DummyLogger()

    with pytest.raises(ConfigurationError):
        check_config_health(settings, logger)


def test_jwks_with_hs256_warning() -> None:
    """Should warn when JWKS is useless with HS256."""
    settings = DummySettings(
        ACCESS_TOKEN_ALGORITHM="HS256",
        JWKS_URI="https://example.com/jwks",
        TOKEN_MODE="stateful",
        REDIS_HOST="localhost",
        REDIS_PASSWORD="pass",
    )

    logger = DummyLogger()

    check_config_health(settings, logger)

    assert any("JWKS_URI is set but" in w for w in logger.warnings)


def test_consumer_with_private_key_is_fatal() -> None:
    """Consumer role must not hold a private key — should raise ConfigurationError."""
    settings = DummySettings(
        ACCESS_TOKEN_ALGORITHM="RS256",
        ACCESS_PRIVATE_KEY_FILE="/opt/keys/private.pem",
        ACCESS_PUBLIC_KEY="dummy-pub-key",
        JWKS_URI="https://auth.example.com/.well-known/jwks.json",
        AUTH_SERVICE_ROLE="consumer",
        TOKEN_MODE="stateful",
        REDIS_HOST="localhost",
        REDIS_PASSWORD="pass",
    )

    logger = DummyLogger()

    with pytest.raises(ConfigurationError):
        check_config_health(settings, logger)

    assert any("must not hold a signing private key" in e for e in logger.criticals)


def test_issuer_rs256_without_private_key_is_fatal() -> None:
    """Issuer role with RS256 but no private key should raise ConfigurationError."""
    settings = DummySettings(
        ACCESS_TOKEN_ALGORITHM="RS256",
        ACCESS_PUBLIC_KEY="dummy-pub-key",
        ACCESS_PRIVATE_KEY_FILE=None,
        JWKS_URI=None,
        AUTH_SERVICE_ROLE="issuer",
        TOKEN_MODE="stateful",
        REDIS_HOST="localhost",
        REDIS_PASSWORD="pass",
    )

    logger = DummyLogger()

    with pytest.raises(ConfigurationError):
        check_config_health(settings, logger)

    assert any("issuers must hold the signing key" in e for e in logger.criticals)


def test_issuer_with_jwks_uri_warns() -> None:
    """Issuer role with JWKS_URI set should log a warning (unusual but not fatal)."""
    settings = DummySettings(
        ACCESS_TOKEN_ALGORITHM="RS256",
        ACCESS_PUBLIC_KEY="dummy-pub-key",
        ACCESS_PRIVATE_KEY_FILE="/opt/keys/private.pem",
        JWKS_URI="https://other-auth.example.com/.well-known/jwks.json",
        AUTH_SERVICE_ROLE="issuer",
        TOKEN_MODE="stateful",
        REDIS_HOST="localhost",
        REDIS_PASSWORD="pass",
    )

    logger = DummyLogger()

    check_config_health(settings, logger)

    assert any("AUTH_SERVICE_ROLE=issuer has JWKS_URI" in w for w in logger.warnings)


def test_missing_redis_fatal() -> None:
    """Should fail when stateful mode has no Redis config."""
    settings = DummySettings(
        ACCESS_TOKEN_ALGORITHM="HS256",
        TOKEN_MODE="stateful",
        REDIS_HOST="",
        REDIS_PASSWORD=None,
    )

    logger = DummyLogger()

    with pytest.raises(ConfigurationError):
        check_config_health(settings, logger)


def test_low_jwks_cache_ttl_warning() -> None:
    """Should warn when JWKS cache TTL is too low."""
    settings = DummySettings(
        ACCESS_TOKEN_ALGORITHM="RS256",
        JWKS_URI="https://example.com/jwks",
        ACCESS_PUBLIC_KEY="key",
        AUTH_SERVICE_ROLE="consumer",
        TOKEN_MODE="stateful",
        REDIS_HOST="localhost",
        REDIS_PASSWORD="pass",
        JWKS_CACHE_TTL_SECONDS=5,
    )

    logger = DummyLogger()

    check_config_health(settings, logger)

    assert any("JWKS_CACHE_TTL_SECONDS" in w for w in logger.warnings)


def test_multiple_fatal_errors_combined() -> None:
    """Should collect multiple fatal errors and raise once."""
    settings = DummySettings(
        ACCESS_TOKEN_ALGORITHM="RS256",
        ACCESS_PUBLIC_KEY=None,
        JWKS_URI=None,
        TOKEN_MODE="stateful",
        REDIS_HOST="",
        REDIS_PASSWORD=None,
    )

    logger = DummyLogger()

    with pytest.raises(ConfigurationError):
        check_config_health(settings, logger)

    # Should have logged multiple critical messages
    assert len(logger.criticals) >= 1


# ── _load_pem_files ───────────────────────────────────────────────────────────


def test_pem_files_loaded_from_disk(tmp_path: Path) -> None:
    """ACCESS_PRIVATE/PUBLIC_KEY properties return content from *_FILE paths."""
    priv = tmp_path / "private.pem"
    pub = tmp_path / "public.pem"
    priv.write_text(RSA_PRIVATE_PEM.strip())
    pub.write_text(RSA_PUBLIC_PEM.strip())

    s = IsolatedSettings(
        **{
            **VALID_SETTINGS_KWARGS,
            "ACCESS_SECRET_KEY": None,
            "ACCESS_TOKEN_ALGORITHM": "RS256",
            "ACCESS_PRIVATE_KEY_FILE": str(priv),
            "ACCESS_PUBLIC_KEY_FILE": str(pub),
        }
    )
    assert s.ACCESS_PRIVATE_KEY is not None
    assert "BEGIN RSA PRIVATE KEY" in s.ACCESS_PRIVATE_KEY.get_secret_value()
    assert "BEGIN PUBLIC KEY" in (s.ACCESS_PUBLIC_KEY or "")


def test_pem_private_file_missing_raises(tmp_path: Path) -> None:
    """Should raise ValueError when ACCESS_PRIVATE_KEY_FILE path does not exist."""
    with pytest.raises(Exception, match="ACCESS_PRIVATE_KEY_FILE not found"):
        IsolatedSettings(
            **{
                **VALID_SETTINGS_KWARGS,
                "ACCESS_SECRET_KEY": None,
                "ACCESS_TOKEN_ALGORITHM": "RS256",
                "ACCESS_PRIVATE_KEY_FILE": str(tmp_path / "missing.pem"),
                "ACCESS_PUBLIC_KEY_FILE": str(tmp_path / "also_missing.pem"),
            }
        )


def test_pem_public_file_missing_raises(tmp_path: Path) -> None:
    """Should raise ValueError when ACCESS_PUBLIC_KEY_FILE path does not exist."""
    priv = tmp_path / "private.pem"
    priv.write_text("PRIVATE_PEM_CONTENT")

    with pytest.raises(Exception, match="ACCESS_PUBLIC_KEY_FILE not found"):
        IsolatedSettings(
            **{
                **VALID_SETTINGS_KWARGS,
                "ACCESS_SECRET_KEY": None,
                "ACCESS_TOKEN_ALGORITHM": "RS256",
                "ACCESS_PRIVATE_KEY_FILE": str(priv),
                "ACCESS_PUBLIC_KEY_FILE": str(tmp_path / "missing_public.pem"),
            }
        )


# ── STRICT_PRODUCTION_MODE ────────────────────────────────────────────────────


def _strict_base(**overrides) -> DummySettings:
    """Minimal valid settings with STRICT_PRODUCTION_MODE enabled."""
    defaults = dict(
        ACCESS_TOKEN_ALGORITHM="HS256",
        TOKEN_MODE="stateful",
        REDIS_HOST="localhost",
        REDIS_PASSWORD="pass",
        JWKS_CACHE_TTL_SECONDS=300,
        STRICT_PRODUCTION_MODE=True,
        ENVIRONMENT="production",
        ALLOWED_ORIGINS=["https://example.com"],
        SESSION_COOKIE_SECURE=True,
        SET_DOCS=False,
        SET_OPEN_API=False,
        TOKEN_ISSUER="https://auth.example.com",
        TOKEN_AUDIENCE="https://api.example.com",
    )
    defaults.update(overrides)
    return DummySettings(**defaults)


def test_strict_mode_clean_production_passes() -> None:
    """Properly hardened production config should pass with strict mode on."""
    settings = _strict_base()
    logger = DummyLogger()
    check_config_health(settings, logger)
    assert logger.warnings == []
    assert logger.criticals == []


def test_strict_mode_set_docs_production_is_fatal() -> None:
    """SET_DOCS=true in production with strict mode should be fatal."""
    settings = _strict_base(SET_DOCS=True)
    logger = DummyLogger()
    with pytest.raises(ConfigurationError):
        check_config_health(settings, logger)
    assert any("SET_DOCS=true" in e for e in logger.criticals)


def test_strict_mode_set_open_api_production_is_fatal() -> None:
    """SET_OPEN_API=true in production with strict mode should be fatal."""
    settings = _strict_base(SET_OPEN_API=True)
    logger = DummyLogger()
    with pytest.raises(ConfigurationError):
        check_config_health(settings, logger)
    assert any("SET_OPEN_API=true" in e for e in logger.criticals)


def test_normal_mode_set_docs_production_is_warning() -> None:
    """SET_DOCS=true in production without strict mode should only warn."""
    settings = DummySettings(
        ACCESS_TOKEN_ALGORITHM="HS256",
        TOKEN_MODE="stateful",
        REDIS_HOST="localhost",
        REDIS_PASSWORD="pass",
        JWKS_CACHE_TTL_SECONDS=300,
        STRICT_PRODUCTION_MODE=False,
        ENVIRONMENT="production",
        ALLOWED_ORIGINS=["https://example.com"],
        SESSION_COOKIE_SECURE=True,
        SET_DOCS=True,
        SET_OPEN_API=False,
    )
    logger = DummyLogger()
    check_config_health(settings, logger)
    assert any("SET_DOCS=true" in w for w in logger.warnings)
    assert logger.criticals == []


def test_serve_docs_in_production_opt_in_warns_not_fatal_under_strict() -> None:
    """SERVE_DOCS_IN_PRODUCTION=true under STRICT serves docs — warns, never fatal."""
    settings = _strict_base(SERVE_DOCS_IN_PRODUCTION=True, SET_DOCS=True)
    logger = DummyLogger()
    check_config_health(settings, logger)  # must NOT raise
    assert any("SERVE_DOCS_IN_PRODUCTION=true" in w for w in logger.warnings)
    assert logger.criticals == []


def test_serve_docs_in_production_opt_in_warns_normal_mode() -> None:
    """Opt-in in normal production mode emits the risk warning, no fatal."""
    settings = DummySettings(
        ACCESS_TOKEN_ALGORITHM="HS256",
        TOKEN_MODE="stateful",
        REDIS_HOST="localhost",
        REDIS_PASSWORD="pass",
        JWKS_CACHE_TTL_SECONDS=300,
        STRICT_PRODUCTION_MODE=False,
        ENVIRONMENT="production",
        ALLOWED_ORIGINS=["https://example.com"],
        SESSION_COOKIE_SECURE=True,
        SERVE_DOCS_IN_PRODUCTION=True,
        SET_DOCS=True,
        SET_OPEN_API=True,
    )
    logger = DummyLogger()
    check_config_health(settings, logger)
    assert any("SERVE_DOCS_IN_PRODUCTION=true" in w for w in logger.warnings)
    assert logger.criticals == []


def test_serve_docs_in_production_opt_in_no_docs_no_warning() -> None:
    """Opt-in with every docs flag off serves nothing — no risk warning."""
    settings = _strict_base(
        SERVE_DOCS_IN_PRODUCTION=True,
        SET_DOCS=False,
        SET_OPEN_API=False,
        SET_REDOC=False,
    )
    logger = DummyLogger()
    check_config_health(settings, logger)
    assert not any("SERVE_DOCS_IN_PRODUCTION" in w for w in logger.warnings)
    assert logger.criticals == []


def test_strict_mode_issuer_with_jwks_uri_is_fatal() -> None:
    """Issuer with JWKS_URI set should be fatal under strict mode."""
    settings = _strict_base(
        ACCESS_TOKEN_ALGORITHM="RS256",
        ACCESS_PUBLIC_KEY="dummy-pub-key",
        ACCESS_PRIVATE_KEY_FILE="/opt/keys/private.pem",
        JWKS_URI="https://other-auth.example.com/.well-known/jwks.json",
        AUTH_SERVICE_ROLE="issuer",
    )
    logger = DummyLogger()
    with pytest.raises(ConfigurationError):
        check_config_health(settings, logger)
    assert any("JWKS_URI set" in e for e in logger.criticals)


def test_normal_mode_issuer_with_jwks_uri_is_warning() -> None:
    """Issuer with JWKS_URI set should only warn without strict mode."""
    settings = DummySettings(
        ACCESS_TOKEN_ALGORITHM="RS256",
        ACCESS_PUBLIC_KEY="dummy-pub-key",
        ACCESS_PRIVATE_KEY_FILE="/opt/keys/private.pem",
        JWKS_URI="https://other-auth.example.com/.well-known/jwks.json",
        AUTH_SERVICE_ROLE="issuer",
        TOKEN_MODE="stateful",
        REDIS_HOST="localhost",
        REDIS_PASSWORD="pass",
        JWKS_CACHE_TTL_SECONDS=300,
        STRICT_PRODUCTION_MODE=False,
    )
    logger = DummyLogger()
    check_config_health(settings, logger)
    assert any("AUTH_SERVICE_ROLE=issuer has JWKS_URI" in w for w in logger.warnings)
    assert logger.criticals == []


def test_strict_mode_wildcard_cors_is_fatal() -> None:
    """Wildcard CORS origin should be fatal under strict mode."""
    settings = _strict_base(ALLOWED_ORIGINS=["*"])
    logger = DummyLogger()
    with pytest.raises(ConfigurationError):
        check_config_health(settings, logger)
    assert any("wildcard" in e for e in logger.criticals)


def test_strict_mode_insecure_cookie_non_local_is_fatal() -> None:
    """SESSION_COOKIE_SECURE=false outside local env should be fatal in strict mode."""
    settings = _strict_base(ENVIRONMENT="staging", SESSION_COOKIE_SECURE=False)
    logger = DummyLogger()
    with pytest.raises(ConfigurationError):
        check_config_health(settings, logger)
    assert any("SESSION_COOKIE_SECURE=false" in e for e in logger.criticals)


def test_strict_mode_insecure_cookie_local_is_allowed() -> None:
    """SESSION_COOKIE_SECURE=false in local env should not fail even with strict mode."""
    settings = _strict_base(ENVIRONMENT="local", SESSION_COOKIE_SECURE=False)
    logger = DummyLogger()
    check_config_health(settings, logger)
    assert not any("SESSION_COOKIE_SECURE" in e for e in logger.criticals)


# ── _assert_key_strength ──────────────────────────────────────────────────────


def test_assert_key_strength_invalid_pem() -> None:
    from auth_sdk_m8.core.config import _assert_key_strength

    with pytest.raises(ValueError, match="Cannot parse PEM key material"):
        _assert_key_strength("not-a-pem-at-all", "RS256", is_private=False)


def test_assert_key_strength_rs256_ec_key() -> None:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from auth_sdk_m8.core.config import _assert_key_strength

    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_pem = (
        ec_key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    with pytest.raises(ValueError, match="RS256 requires an RSA key"):
        _assert_key_strength(ec_pem, "RS256", is_private=False)


def test_assert_key_strength_rsa_too_small() -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from auth_sdk_m8.core.config import _assert_key_strength

    small_key = rsa.generate_private_key(65537, 1024)
    small_pem = (
        small_key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    with pytest.raises(ValueError, match="2048-bit"):
        _assert_key_strength(small_pem, "RS256", is_private=False)


def test_assert_key_strength_es256_rsa_key() -> None:
    from auth_sdk_m8.core.config import _assert_key_strength

    with pytest.raises(ValueError, match="ES256 requires an EC key"):
        _assert_key_strength(RSA_PUBLIC_PEM.strip(), "ES256", is_private=False)


def test_assert_key_strength_es256_wrong_curve() -> None:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from auth_sdk_m8.core.config import _assert_key_strength

    wrong_curve_key = ec.generate_private_key(ec.SECP384R1())
    wrong_pem = (
        wrong_curve_key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    with pytest.raises(ValueError, match="P-256"):
        _assert_key_strength(wrong_pem, "ES256", is_private=False)


def test_assert_key_strength_hs256_is_noop() -> None:
    """algo not in {RS256, ES256} → function exits without any check (193->exit)."""
    from auth_sdk_m8.core.config import _assert_key_strength

    _assert_key_strength(RSA_PUBLIC_PEM.strip(), "HS256", is_private=False)


def test_assert_key_strength_es256_valid_p256_key() -> None:
    """Valid P-256 EC key → isinstance check is False, function exits cleanly (200->exit)."""
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    from auth_sdk_m8.core.config import _assert_key_strength

    key = ec.generate_private_key(ec.SECP256R1())
    pem = (
        key.public_key()
        .public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    _assert_key_strength(pem, "ES256", is_private=False)


# ── _sync_token_algorithms ────────────────────────────────────────────────────


def test_sync_token_algorithms_seeds_access_when_at_default() -> None:
    """Deprecated TOKEN_ALGORITHM seeds ACCESS only when ACCESS is at default.

    Refresh tokens are internal and must never inherit the asymmetric algorithm.
    """
    kwargs = {
        **VALID_SETTINGS_KWARGS,
        "TOKEN_ALGORITHM": "ES256",
        "ACCESS_TOKEN_ALGORITHM": "RS256",  # default sentinel → eligible for seeding
        "ACCESS_SECRET_KEY": None,
        "JWKS_URI": "https://auth.example.com/.well-known/jwks.json",
    }
    s = IsolatedSettings(**kwargs)
    assert s.ACCESS_TOKEN_ALGORITHM == "ES256"
    assert s.REFRESH_TOKEN_ALGORITHM == "HS256"


def test_sync_token_algorithms_rejects_direct_asymmetric_refresh() -> None:
    kwargs = {**VALID_SETTINGS_KWARGS, "REFRESH_TOKEN_ALGORITHM": "RS256"}
    with pytest.raises(ValueError, match="REFRESH_TOKEN_ALGORITHM must be HS256"):
        IsolatedSettings(**kwargs)


def test_sync_token_algorithms_both_already_non_hs256() -> None:
    """ACCESS and REFRESH both pre-set to non-HS256 → sync skips both lines (507->509, 509->511)."""
    kwargs = {
        **VALID_SETTINGS_KWARGS,
        "TOKEN_ALGORITHM": "RS256",
        "ACCESS_TOKEN_ALGORITHM": "RS256",
        "REFRESH_TOKEN_ALGORITHM": "RS256",
    }
    with pytest.raises(ValueError, match="REFRESH_TOKEN_ALGORITHM must be HS256"):
        IsolatedSettings(**kwargs)


# ── _validate_key_material ────────────────────────────────────────────────────


def test_validate_key_material_hs256_no_secret_key() -> None:
    kwargs = {
        k: v for k, v in VALID_SETTINGS_KWARGS.items() if k != "ACCESS_SECRET_KEY"
    }
    with pytest.raises(Exception, match="ACCESS_SECRET_KEY is required"):
        IsolatedSettings(**kwargs)


def test_validate_key_material_rs256_no_key_source() -> None:
    kwargs = {**VALID_SETTINGS_KWARGS, "ACCESS_TOKEN_ALGORITHM": "RS256"}
    with pytest.raises(Exception, match="requires a public key source"):
        IsolatedSettings(**kwargs)


# ── _validate_key_strength (public-key-only path) ────────────────────────────


def test_validate_key_strength_public_key_only(tmp_path) -> None:
    pub = tmp_path / "public.pem"
    pub.write_text(RSA_PUBLIC_PEM.strip())
    kwargs = {
        **VALID_SETTINGS_KWARGS,
        "ACCESS_TOKEN_ALGORITHM": "RS256",
        "ACCESS_SECRET_KEY": None,
        "ACCESS_PUBLIC_KEY_FILE": str(pub),
    }
    s = IsolatedSettings(**kwargs)
    assert s.ACCESS_PUBLIC_KEY is not None


def test_validate_key_strength_jwks_uri_only_no_local_key() -> None:
    """RS256 consumer with JWKS_URI only (no local keys) → elif branch is False (581->584)."""
    kwargs = {
        **VALID_SETTINGS_KWARGS,
        "ACCESS_TOKEN_ALGORITHM": "RS256",
        "ACCESS_SECRET_KEY": None,
        "JWKS_URI": "https://auth.example.com/.well-known/jwks.json",
    }
    s = IsolatedSettings(**kwargs)
    assert s.ACCESS_TOKEN_ALGORITHM == "RS256"
    assert s.ACCESS_PUBLIC_KEY is None


# ── enforce_secure_and_required_values ────────────────────────────────────────


class _RequiredCustomField(IsolatedSettings):
    """Subclass exposing an Optional field as required (no pattern constraint)."""

    CUSTOM_FIELD: str = "present"
    required_fields: ClassVar = ["CUSTOM_FIELD"]
    secret_fields: ClassVar = []
    passwords: ClassVar = []
    secret_keys: ClassVar = []


def test_enforce_required_field_empty_raises() -> None:
    with pytest.raises(Exception, match="must be provided"):
        _RequiredCustomField(**{**VALID_SETTINGS_KWARGS, "CUSTOM_FIELD": ""})


class _SecretCustomField(IsolatedSettings):
    """Subclass with a custom secret not subject to strength checks."""

    CUSTOM_SECRET: Optional[str] = None
    required_fields: ClassVar = []
    secret_fields: ClassVar = ["CUSTOM_SECRET"]
    passwords: ClassVar = []
    secret_keys: ClassVar = []


def test_enforce_insecure_default_secret_raises() -> None:
    with pytest.raises(Exception, match="Insecure default"):
        _SecretCustomField(**{**VALID_SETTINGS_KWARGS, "CUSTOM_SECRET": "changethis"})


# ── check_config_health: production deployment checks ────────────────────────


def test_production_localhost_cors_is_fatal() -> None:
    settings = DummySettings(
        ACCESS_TOKEN_ALGORITHM="HS256",
        TOKEN_MODE="stateless",
        ENVIRONMENT="production",
        ALLOWED_ORIGINS=["http://localhost:3000"],
    )
    logger = DummyLogger()
    with pytest.raises(ConfigurationError):
        check_config_health(settings, logger)


def test_production_set_open_api_warns_non_strict() -> None:
    settings = DummySettings(
        ACCESS_TOKEN_ALGORITHM="HS256",
        TOKEN_MODE="stateless",
        ENVIRONMENT="production",
        ALLOWED_ORIGINS=[],
        SET_DOCS=False,
        SET_OPEN_API=True,
        STRICT_PRODUCTION_MODE=False,
    )
    logger = DummyLogger()
    check_config_health(settings, logger)
    assert any("SET_OPEN_API" in w for w in logger.warnings)


def test_consumer_stateless_with_db_host_warns() -> None:
    settings = DummySettings(
        ACCESS_TOKEN_ALGORITHM="HS256",
        TOKEN_MODE="stateless",
        AUTH_SERVICE_ROLE="consumer",
        DB_HOST="localhost",
    )
    logger = DummyLogger()
    check_config_health(settings, logger)
    assert any("DB_HOST" in w for w in logger.warnings)


# ── _check_rate_limit_config ─────────────────────────────────────────────────


def _rl_settings(**kwargs) -> DummySettings:
    """Base settings with safe defaults for rate-limit health-check tests."""
    base = {
        "ACCESS_TOKEN_ALGORITHM": "HS256",
        "TOKEN_MODE": "stateful",
        "REDIS_HOST": "localhost",
        "REDIS_PASSWORD": "pass",
        "JWKS_CACHE_TTL_SECONDS": 300,
    }
    base.update(kwargs)
    return DummySettings(**base)


def test_rate_limit_default_values_no_warning() -> None:
    """Defaults (login 5/15 min, refresh 10/5 min) must not trigger a warning."""
    settings = _rl_settings(
        LOGIN_RATE_LIMIT_REQUESTS=5,
        LOGIN_RATE_LIMIT_WINDOW_MINUTES=15,
        REFRESH_RATE_LIMIT_REQUESTS=10,
        REFRESH_RATE_LIMIT_WINDOW_MINUTES=5,
    )
    logger = DummyLogger()
    check_config_health(settings, logger)
    assert not any("RATE_LIMIT" in w for w in logger.warnings)


def test_rate_limit_permissive_login_warns() -> None:
    """LOGIN effective rate > 5 req/min must produce a warning."""
    settings = _rl_settings(
        LOGIN_RATE_LIMIT_REQUESTS=100,
        LOGIN_RATE_LIMIT_WINDOW_MINUTES=1,
    )
    logger = DummyLogger()
    check_config_health(settings, logger)
    assert any("LOGIN_RATE_LIMIT_REQUESTS" in w for w in logger.warnings)
    assert any("highly permissive" in w for w in logger.warnings)


def test_rate_limit_permissive_refresh_warns() -> None:
    """REFRESH effective rate > 20 req/min must produce a warning."""
    settings = _rl_settings(
        REFRESH_RATE_LIMIT_REQUESTS=100,
        REFRESH_RATE_LIMIT_WINDOW_MINUTES=1,
    )
    logger = DummyLogger()
    check_config_health(settings, logger)
    assert any("REFRESH_RATE_LIMIT_REQUESTS" in w for w in logger.warnings)


def test_rate_limit_stateless_skips_refresh_check() -> None:
    """In stateless mode, permissive refresh settings must not warn (no refresh tokens)."""
    settings = _rl_settings(
        TOKEN_MODE="stateless",
        REFRESH_RATE_LIMIT_REQUESTS=1000,
        REFRESH_RATE_LIMIT_WINDOW_MINUTES=1,
    )
    logger = DummyLogger()
    check_config_health(settings, logger)
    assert not any("REFRESH_RATE_LIMIT" in w for w in logger.warnings)


def test_rate_limit_exactly_at_threshold_no_warning() -> None:
    """Effective rate == threshold must not trigger a warning (> not >=)."""
    # Login: 5 req/min exactly
    settings = _rl_settings(
        LOGIN_RATE_LIMIT_REQUESTS=5,
        LOGIN_RATE_LIMIT_WINDOW_MINUTES=1,
        REFRESH_RATE_LIMIT_REQUESTS=20,
        REFRESH_RATE_LIMIT_WINDOW_MINUTES=1,
    )
    logger = DummyLogger()
    check_config_health(settings, logger)
    assert not any("RATE_LIMIT" in w for w in logger.warnings)


# ── _build_vault_source ───────────────────────────────────────────────────────


def test_build_vault_source_returns_callable() -> None:
    mock_hvac = MagicMock()
    mock_client = MagicMock()
    mock_hvac.Client.return_value = mock_client
    mock_client.secrets.kv.v2.read_secret_version.return_value = {
        "data": {"data": {"ACCESS_SECRET_KEY": "built-val"}}
    }

    with patch.dict(sys.modules, {"hvac": mock_hvac}):
        source = _build_vault_source("http://vault:8200", "mytoken")
        result = source()

    assert "ACCESS_SECRET_KEY" in result


# ── *_FILE secret source (_read_secret_file / _build_file_secret_source) ───────


def test_read_secret_file_returns_stripped_contents(tmp_path: Path) -> None:
    secret = tmp_path / "db_password"
    secret.write_text("  s3cret-value\n", encoding="utf-8")
    assert _read_secret_file(str(secret), "DB_PASSWORD") == "s3cret-value"


def test_read_secret_file_missing_raises(tmp_path: Path) -> None:
    missing = tmp_path / "absent"
    with pytest.raises(ValueError, match="DB_PASSWORD_FILE points to a missing file"):
        _read_secret_file(str(missing), "DB_PASSWORD")


def test_file_secret_source_maps_file_env_to_field(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret = tmp_path / "secret"
    secret.write_text("file-sourced\n", encoding="utf-8")
    monkeypatch.setenv("DB_PASSWORD_FILE", str(secret))
    source = _build_file_secret_source(CommonSettings)
    assert source() == {"DB_PASSWORD": "file-sourced"}


def test_file_secret_source_empty_when_no_file_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("DB_PASSWORD_FILE", raising=False)
    source = _build_file_secret_source(CommonSettings)
    assert source() == {}


def test_file_secret_source_ignores_unknown_fields(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    secret = tmp_path / "secret"
    secret.write_text("nope", encoding="utf-8")
    monkeypatch.setenv("NOT_A_FIELD_FILE", str(secret))
    source = _build_file_secret_source(CommonSettings)
    assert source() == {}


def test_file_secret_source_end_to_end_overrides_env(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A `*_FILE` mount overrides a plaintext env value for the same field."""
    secret = tmp_path / "redis_password"
    secret.write_text(f"{VALID_PASSWORD}\n", encoding="utf-8")

    class FileSettings(CommonSettings):
        model_config = SettingsConfigDict(env_file=None)

    env = {**VALID_SETTINGS_KWARGS, "REDIS_PASSWORD": "WrongPlain1!"}
    for key, value in env.items():
        monkeypatch.setenv(key, str(value))
    monkeypatch.setenv("REDIS_PASSWORD_FILE", str(secret))
    monkeypatch.delenv("SECRET_PROVIDER", raising=False)

    settings = FileSettings()  # type: ignore[call-arg]
    assert settings.REDIS_PASSWORD is not None
    assert settings.REDIS_PASSWORD.get_secret_value() == VALID_PASSWORD


def test_file_secret_source_missing_file_fails_construction(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Pointing `*_FILE` at an absent file fails closed at settings construction."""

    class FileSettings(CommonSettings):
        model_config = SettingsConfigDict(env_file=None)

    for key, value in VALID_SETTINGS_KWARGS.items():
        monkeypatch.setenv(key, str(value))
    monkeypatch.setenv("REDIS_PASSWORD_FILE", str(tmp_path / "absent"))
    monkeypatch.delenv("SECRET_PROVIDER", raising=False)

    with pytest.raises(
        ValueError, match="REDIS_PASSWORD_FILE points to a missing file"
    ):
        FileSettings()  # type: ignore[call-arg]


# ── CommonSettings.settings_customise_sources ─────────────────────────────────


def test_common_settings_customise_sources_no_vault(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "local")
    monkeypatch.delenv("SECRET_PROVIDER", raising=False)

    sources = CommonSettings.settings_customise_sources(
        CommonSettings,
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
    )

    assert len(sources) == 5


def test_common_settings_customise_sources_vault(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SECRET_PROVIDER", "vault")
    monkeypatch.setenv("VAULT_ADDR", "http://vault:8200")
    monkeypatch.setenv("VAULT_TOKEN", "mytoken")

    mock_hvac = MagicMock()
    mock_hvac.Client.return_value = MagicMock()

    with patch.dict(sys.modules, {"hvac": mock_hvac}):
        sources = CommonSettings.settings_customise_sources(
            CommonSettings,
            MagicMock(),
            MagicMock(),
            MagicMock(),
            MagicMock(),
        )

    assert len(sources) == 6


def test_common_settings_customise_sources_vault_token_from_file(
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

        sources = CommonSettings.settings_customise_sources(
            CommonSettings,
            MagicMock(),
            MagicMock(),
            MagicMock(),
            MagicMock(),
        )

    assert len(sources) == 6


def test_common_settings_customise_sources_vault_no_addr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vault mode but VAULT_ADDR absent → vault source not appended (651->653)."""
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("SECRET_PROVIDER", "vault")
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.delenv("VAULT_TOKEN", raising=False)

    sources = CommonSettings.settings_customise_sources(
        CommonSettings,
        MagicMock(),
        MagicMock(),
        MagicMock(),
        MagicMock(),
    )

    assert len(sources) == 5


# ── new OAuth / CORS validator string-parsing branches ───────────────────────


def test_parse_redirect_schemes_from_string() -> None:
    """String env value → list parsing (line 269 branch)."""
    result = CommonSettings.parse_redirect_schemes("chrome-extension://,myapp://")
    assert result == ["chrome-extension://", "myapp://"]


def test_parse_redirect_prefixes_from_string() -> None:
    """String env value → list parsing (line 282 branch)."""
    result = CommonSettings.parse_redirect_prefixes(
        "chrome-extension://abc123/,chrome-extension://def456/"
    )
    assert result == [
        "chrome-extension://abc123/",
        "chrome-extension://def456/",
    ]


def test_parse_cors_origin_schemes_from_string() -> None:
    """String env value → list parsing (line 296 branch)."""
    result = CommonSettings.parse_cors_origin_schemes("chrome-extension://")
    assert result == ["chrome-extension://"]


# ── consumer+stateless with no DB_HOST (config_health.py 75->83) ─────────────


def test_consumer_stateless_without_db_host_no_warning() -> None:
    """consumer + stateless with empty DB_HOST → db_host branch is False (75->83)."""
    settings = DummySettings(
        ACCESS_TOKEN_ALGORITHM="HS256",
        TOKEN_MODE="stateless",
        AUTH_SERVICE_ROLE="consumer",
    )
    logger = DummyLogger()
    check_config_health(settings, logger)
    assert not any("DB_HOST" in w for w in logger.warnings)


# ── requires_redis role-aware behaviour ──────────────────────────────────────


_BASE_NO_REDIS = {k: v for k, v in VALID_SETTINGS_KWARGS.items() if "REDIS" not in k}


@pytest.mark.parametrize("mode", ["stateless", "stateful", "hybrid"])
def test_requires_redis_consumer_always_false(mode: str) -> None:
    """Consumer services never need local Redis regardless of TOKEN_MODE."""
    s = IsolatedSettings(
        **{**_BASE_NO_REDIS, "AUTH_SERVICE_ROLE": "consumer", "TOKEN_MODE": mode}
    )
    assert s.requires_redis is False


def test_requires_redis_issuer_stateful_true() -> None:
    s = IsolatedSettings(
        **{
            **VALID_SETTINGS_KWARGS,
            "AUTH_SERVICE_ROLE": "issuer",
            "TOKEN_MODE": "stateful",
        }
    )
    assert s.requires_redis is True


def test_requires_redis_issuer_hybrid_true() -> None:
    s = IsolatedSettings(
        **{
            **VALID_SETTINGS_KWARGS,
            "AUTH_SERVICE_ROLE": "issuer",
            "TOKEN_MODE": "hybrid",
        }
    )
    assert s.requires_redis is True


def test_requires_redis_issuer_stateless_false() -> None:
    s = IsolatedSettings(
        **{**_BASE_NO_REDIS, "AUTH_SERVICE_ROLE": "issuer", "TOKEN_MODE": "stateless"}
    )
    assert s.requires_redis is False


# ── _enforce_redis_for_issuers validator ─────────────────────────────────────


def test_enforce_redis_issuer_stateful_no_redis_raises() -> None:
    """issuer + stateful without REDIS_* must raise ValidationError."""
    with pytest.raises(Exception, match="requires all REDIS_\\* fields"):
        IsolatedSettings(
            **{
                **_BASE_NO_REDIS,
                "AUTH_SERVICE_ROLE": "issuer",
                "TOKEN_MODE": "stateful",
            }
        )


def test_enforce_redis_issuer_hybrid_no_redis_raises() -> None:
    """issuer + hybrid without REDIS_* must raise ValidationError."""
    with pytest.raises(Exception, match="requires all REDIS_\\* fields"):
        IsolatedSettings(
            **{**_BASE_NO_REDIS, "AUTH_SERVICE_ROLE": "issuer", "TOKEN_MODE": "hybrid"}
        )


def test_enforce_redis_issuer_stateless_no_redis_ok() -> None:
    """issuer + stateless does not need Redis — must start without error."""
    s = IsolatedSettings(
        **{**_BASE_NO_REDIS, "AUTH_SERVICE_ROLE": "issuer", "TOKEN_MODE": "stateless"}
    )
    assert s.requires_redis is False


def test_enforce_redis_consumer_stateful_no_redis_ok() -> None:
    """consumer + stateful does not need local Redis — must start without error."""
    s = IsolatedSettings(
        **{**_BASE_NO_REDIS, "AUTH_SERVICE_ROLE": "consumer", "TOKEN_MODE": "stateful"}
    )
    assert s.requires_redis is False


def test_enforce_redis_issuer_empty_password_raises() -> None:
    """Empty REDIS_PASSWORD string is treated as missing (SecretStr truthy trap)."""
    from pydantic import SecretStr as _SecretStr

    kwargs = {
        **_BASE_NO_REDIS,
        "REDIS_HOST": "localhost",
        "REDIS_PORT": 6379,
        "REDIS_USER": "appuser",
        "REDIS_PASSWORD": _SecretStr(""),
    }
    with pytest.raises(Exception, match="requires all REDIS_\\* fields"):
        IsolatedSettings(**{**kwargs, "TOKEN_MODE": "stateful"})


def test_enforce_redis_issuer_stateful_with_all_fields_ok() -> None:
    """issuer + stateful with all REDIS_* provided must start without error."""
    s = IsolatedSettings(**{**VALID_SETTINGS_KWARGS, "TOKEN_MODE": "stateful"})
    assert s.requires_redis is True


# ── _check_token_boundary_config ─────────────────────────────────────────────


def _prod_settings(**kwargs) -> DummySettings:
    """Base production-like settings for token boundary tests."""
    base = {
        "ACCESS_TOKEN_ALGORITHM": "HS256",
        "TOKEN_MODE": "stateless",
        "ENVIRONMENT": "production",
        "ALLOWED_ORIGINS": [],
        "SET_DOCS": False,
        "SET_OPEN_API": False,
        "STRICT_PRODUCTION_MODE": False,
    }
    base.update(kwargs)
    return DummySettings(**base)


def test_token_boundary_no_warning_in_local() -> None:
    """TOKEN_ISSUER/AUDIENCE unset in local environment → no warning."""
    settings = DummySettings(
        ACCESS_TOKEN_ALGORITHM="HS256",
        TOKEN_MODE="stateless",
        ENVIRONMENT="local",
    )
    logger = DummyLogger()
    check_config_health(settings, logger)
    assert not any("TOKEN_ISSUER" in w for w in logger.warnings)
    assert not any("TOKEN_AUDIENCE" in w for w in logger.warnings)


def test_token_boundary_missing_issuer_warns_in_production() -> None:
    """TOKEN_ISSUER unset in production → warning (non-strict)."""
    settings = _prod_settings(TOKEN_AUDIENCE="https://api.example.com")
    logger = DummyLogger()
    check_config_health(settings, logger)
    assert any("TOKEN_ISSUER" in w for w in logger.warnings)
    assert not any("TOKEN_AUDIENCE" in w for w in logger.warnings)


def test_token_boundary_missing_audience_warns_in_production() -> None:
    """TOKEN_AUDIENCE unset in production → warning (non-strict)."""
    settings = _prod_settings(TOKEN_ISSUER="https://auth.example.com")
    logger = DummyLogger()
    check_config_health(settings, logger)
    assert not any("TOKEN_ISSUER" in w for w in logger.warnings)
    assert any("TOKEN_AUDIENCE" in w for w in logger.warnings)


def test_token_boundary_both_missing_two_warnings() -> None:
    """Neither TOKEN_ISSUER nor TOKEN_AUDIENCE set in production → two warnings."""
    settings = _prod_settings()
    logger = DummyLogger()
    check_config_health(settings, logger)
    assert any("TOKEN_ISSUER" in w for w in logger.warnings)
    assert any("TOKEN_AUDIENCE" in w for w in logger.warnings)


def test_token_boundary_both_set_no_warning() -> None:
    """Both TOKEN_ISSUER and TOKEN_AUDIENCE set in production → no boundary warning."""
    settings = _prod_settings(
        TOKEN_ISSUER="https://auth.example.com",
        TOKEN_AUDIENCE="https://api.example.com",
    )
    logger = DummyLogger()
    check_config_health(settings, logger)
    assert not any("TOKEN_ISSUER" in w for w in logger.warnings)
    assert not any("TOKEN_AUDIENCE" in w for w in logger.warnings)


def test_token_boundary_missing_issuer_fatal_in_strict() -> None:
    """TOKEN_ISSUER unset in strict production → fatal."""
    settings = _prod_settings(
        STRICT_PRODUCTION_MODE=True,
        TOKEN_AUDIENCE="https://api.example.com",
    )
    logger = DummyLogger()
    with pytest.raises(ConfigurationError):
        check_config_health(settings, logger)
    assert any("TOKEN_ISSUER" in e for e in logger.criticals)


def test_token_boundary_missing_audience_fatal_in_strict() -> None:
    """TOKEN_AUDIENCE unset in strict production → fatal."""
    settings = _prod_settings(
        STRICT_PRODUCTION_MODE=True,
        TOKEN_ISSUER="https://auth.example.com",
    )
    logger = DummyLogger()
    with pytest.raises(ConfigurationError):
        check_config_health(settings, logger)
    assert any("TOKEN_AUDIENCE" in e for e in logger.criticals)


# ── effective_set_open_api / effective_set_docs / effective_set_redoc ─────────


def _docs_settings(**overrides) -> IsolatedSettings:
    """Minimal IsolatedSettings for testing effective docs flags."""
    kwargs = {**VALID_SETTINGS_KWARGS, **overrides}
    # Production mode rejects the well-known dev VALID_KEY; swap in a prod-safe key.
    if kwargs.get("ENVIRONMENT") == "production" or kwargs.get(
        "STRICT_PRODUCTION_MODE"
    ):
        for field in ("ACCESS_SECRET_KEY", "REFRESH_SECRET_KEY", "EVENT_SIGNING_KEY"):
            if field not in overrides:
                kwargs[field] = PROD_VALID_KEY
    return IsolatedSettings(**kwargs)


def test_effective_docs_production_env_all_false() -> None:
    """ENVIRONMENT==production gates all three effective flags off."""
    s = _docs_settings(
        ENVIRONMENT="production", SET_OPEN_API=True, SET_DOCS=True, SET_REDOC=True
    )
    assert s.effective_set_open_api is False
    assert s.effective_set_docs is False
    assert s.effective_set_redoc is False


def test_effective_docs_strict_production_mode_all_false() -> None:
    """STRICT_PRODUCTION_MODE=True gates all three effective flags off regardless of ENVIRONMENT."""
    s = _docs_settings(
        ENVIRONMENT="local",
        STRICT_PRODUCTION_MODE=True,
        SET_OPEN_API=True,
        SET_DOCS=True,
        SET_REDOC=True,
    )
    assert s.effective_set_open_api is False
    assert s.effective_set_docs is False
    assert s.effective_set_redoc is False


def test_effective_docs_dev_set_true_all_true() -> None:
    """Non-production + SET_*=True → effective == True."""
    s = _docs_settings(
        ENVIRONMENT="local", SET_OPEN_API=True, SET_DOCS=True, SET_REDOC=True
    )
    assert s.effective_set_open_api is True
    assert s.effective_set_docs is True
    assert s.effective_set_redoc is True


def test_effective_docs_dev_set_false_all_false() -> None:
    """Non-production + SET_*=False → effective == False (configured value respected)."""
    s = _docs_settings(
        ENVIRONMENT="development", SET_OPEN_API=False, SET_DOCS=False, SET_REDOC=False
    )
    assert s.effective_set_open_api is False
    assert s.effective_set_docs is False
    assert s.effective_set_redoc is False


def test_effective_docs_production_overrides_raw_flags() -> None:
    """Production forces False even when SET_*=True (raw flag unchanged)."""
    s = _docs_settings(
        ENVIRONMENT="production", SET_OPEN_API=True, SET_DOCS=True, SET_REDOC=True
    )
    # raw flags are unchanged
    assert s.SET_OPEN_API is True
    assert s.SET_DOCS is True
    assert s.SET_REDOC is True
    # effective flags are gated off
    assert s.effective_set_open_api is False
    assert s.effective_set_docs is False
    assert s.effective_set_redoc is False


def test_effective_docs_staging_not_production() -> None:
    """Staging is not production — effective flags respect configured values."""
    s = _docs_settings(
        ENVIRONMENT="staging", SET_OPEN_API=True, SET_DOCS=False, SET_REDOC=True
    )
    assert s.effective_set_open_api is True
    assert s.effective_set_docs is False
    assert s.effective_set_redoc is True


def test_effective_docs_production_opt_in_serves() -> None:
    """SERVE_DOCS_IN_PRODUCTION=True re-enables docs in production (raw SET_* honored)."""
    s = _docs_settings(
        ENVIRONMENT="production",
        SERVE_DOCS_IN_PRODUCTION=True,
        SET_OPEN_API=True,
        SET_DOCS=True,
        SET_REDOC=True,
    )
    assert s.effective_set_open_api is True
    assert s.effective_set_docs is True
    assert s.effective_set_redoc is True


def test_effective_docs_production_opt_in_respects_raw_flags() -> None:
    """Opt-in lifts the production gate but the raw SET_* flags still apply per-endpoint."""
    s = _docs_settings(
        ENVIRONMENT="production",
        SERVE_DOCS_IN_PRODUCTION=True,
        SET_OPEN_API=False,
        SET_DOCS=True,
        SET_REDOC=False,
    )
    assert s.effective_set_open_api is False
    assert s.effective_set_docs is True
    assert s.effective_set_redoc is False


def test_effective_docs_strict_mode_opt_in_serves() -> None:
    """The opt-in also overrides STRICT_PRODUCTION_MODE gating."""
    s = _docs_settings(
        ENVIRONMENT="local",
        STRICT_PRODUCTION_MODE=True,
        SERVE_DOCS_IN_PRODUCTION=True,
        SET_OPEN_API=True,
        SET_DOCS=True,
        SET_REDOC=True,
    )
    assert s.effective_set_open_api is True
    assert s.effective_set_docs is True
    assert s.effective_set_redoc is True


def test_serve_docs_in_production_defaults_false() -> None:
    """The opt-in is off by default (secure-by-default)."""
    assert _docs_settings().SERVE_DOCS_IN_PRODUCTION is False
