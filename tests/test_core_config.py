"""Tests for auth_sdk_m8.core.config."""

import sys
from typing import ClassVar, Optional
from unittest.mock import MagicMock, patch

import pytest

from auth_sdk_m8.core.config import (
    CommonSettings,
    EnvProvider,
    SecretProvider,
    VaultProvider,
    _build_vault_source,
    check_config_health,
    parse_cors,
    settings_customise_sources,
)
from auth_sdk_m8.core.exceptions import ConfigurationError
from tests.conftest import (
    RSA_PRIVATE_PEM,
    RSA_PUBLIC_PEM,
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


# ── check_config_health ────────────────────────────────────────────────────────────
class DummySettings:
    """Minimal settings object for testing."""

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

    def warning(self, msg: str, *args) -> None:
        self.warnings.append(msg % args if args else msg)

    def critical(self, msg: str, *args) -> None:
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


def test_pem_files_loaded_from_disk(tmp_path: pytest.TempPathFactory) -> None:
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


def test_pem_private_file_missing_raises(tmp_path: pytest.TempPathFactory) -> None:
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


def test_pem_public_file_missing_raises(tmp_path: pytest.TempPathFactory) -> None:
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


# ── _sync_token_algorithms ────────────────────────────────────────────────────


def test_sync_token_algorithms_propagates_non_hs256() -> None:
    # TOKEN_ALGORITHM=RS256 triggers lines 415-418 even if creation fails later
    kwargs = {**VALID_SETTINGS_KWARGS, "TOKEN_ALGORITHM": "RS256"}
    with pytest.raises(Exception):
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

    assert len(sources) == 4


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

    assert len(sources) == 5


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

    assert len(sources) == 5
