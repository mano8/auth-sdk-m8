"""
CommonSettings — base pydantic-settings class for m8 microservices.

Requires the `config` extra:  pip install "auth-sdk-m8[config]"

Usage::

    from pathlib import Path
    from auth_sdk_m8.core.config import CommonSettings
    from auth_sdk_m8.utils.paths import find_dotenv
    from pydantic_settings import SettingsConfigDict

    class Settings(CommonSettings):
        ENV_FILE_DIR = Path(__file__).resolve().parent
        model_config = SettingsConfigDict(
            env_file=find_dotenv(ENV_FILE_DIR),
            env_file_encoding="utf-8",
        )
        MY_API_KEY: str

    settings = Settings()
"""

from os import getenv
from pathlib import Path
from typing import Any, ClassVar, Dict, List, Literal, Optional, Tuple
from urllib.parse import quote_plus

from pydantic import (
    EmailStr,
    Field,
    HttpUrl,
    SecretStr,
    computed_field,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings

from auth_sdk_m8.schemas.shared import ValidationConstants

# ── Secret providers ──────────────────────────────────────────────────────────


class SecretProvider:
    """Abstract base for retrieving secrets from various backends."""

    def get(self, key: str) -> Optional[str]:
        """Return the secret value for *key*, or None if not found."""
        raise NotImplementedError


class EnvProvider(SecretProvider):
    """Fetch secrets from OS environment variables."""

    def get(self, key: str) -> Optional[str]:
        return getenv(key)


class VaultProvider(SecretProvider):
    """Fetch secrets from HashiCorp Vault (production/staging only)."""

    def __init__(self, addr: str, token: str) -> None:
        try:
            import hvac  # noqa: PLC0415
        except ImportError as e:
            raise RuntimeError("hvac library is required for Vault integration") from e
        self._client = hvac.Client(url=addr, token=token)

    def get(self, key: str) -> Optional[str]:
        """Retrieve a secret at ``secret/data/app`` with the given key."""
        result = self._client.secrets.kv.v2.read_secret_version(path="app")
        return result.get("data", {}).get("data", {}).get(key)


def settings_customise_sources(
    init_settings: Any,
    env_settings: Any,
    file_secret_settings: Any,
) -> Tuple[Any, ...]:
    """
    Source priority: init kwargs > .env file > env vars > Vault (prod/staging).
    """
    sources: list[Any] = [init_settings, file_secret_settings, env_settings]
    env = getenv("ENVIRONMENT", "").lower()
    secret_provider = getenv("SECRET_PROVIDER", "").lower()

    if env in {"production", "staging"} and secret_provider == "vault":
        vault_addr = getenv("VAULT_ADDR")
        vault_token = getenv("VAULT_TOKEN")
        token_file = "/run/secrets/vault_token"
        if not vault_token and Path(token_file).is_file():
            vault_token = Path(token_file).read_text(encoding="utf-8").strip()
        if vault_addr and vault_token:
            provider = VaultProvider(vault_addr, vault_token)

            def _vault_source(settings: BaseSettings) -> Dict[str, Any]:
                return {
                    key: val
                    for key in REQUIRE_UPDATE_FIELDS
                    if (val := provider.get(key)) is not None
                }

            sources.append(_vault_source)

    return tuple(sources)


def parse_cors(value: str) -> List[str]:
    """
    Parse a comma-separated CORS origins string into a validated list.

    Each origin is validated against ``HTTP_HOST_REGEX``.

    Raises:
        ValueError: If any origin is invalid or the string is empty.
    """
    host_pattern = ValidationConstants.HTTP_HOST_REGEX
    origins: List[str] = []
    for origin in value.split(","):
        origin = origin.strip().rstrip("/")
        if not origin:
            continue
        if not host_pattern.match(origin):
            raise ValueError(f"Invalid host in BACKEND_CORS_ORIGINS: '{origin}'")
        origins.append(origin)
    if not origins:
        raise ValueError("BACKEND_CORS_ORIGINS must contain at least one valid origin")
    return origins


REQUIRE_UPDATE_FIELDS: List[str] = [
    "ACCESS_SECRET_KEY",
    "DB_PASSWORD",
    "REDIS_PASSWORD",
]


class CommonSettings(BaseSettings):
    """
    Base settings class for all m8 microservices.

    Subclass this in each service and add service-specific fields.
    """

    ENV_FILE_DIR: ClassVar[Path] = Path(__file__).resolve().parent

    required_fields: ClassVar[List[str]] = [
        "DOMAIN",
        "ENVIRONMENT",
        "API_PREFIX",
        "PROJECT_NAME",
        "STACK_NAME",
        "STATIC_BASE_PATH",
        "TEMPLATES_BASE_PATH",
        "FRONTEND_HOST",
    ]
    secret_fields: ClassVar[List[str]] = [
        "ACCESS_SECRET_KEY",
        "ACCESS_PRIVATE_KEY",
        "REFRESH_SECRET_KEY",
        "DB_PASSWORD",
        "REDIS_PASSWORD",
    ]
    passwords: ClassVar[List[str]] = ["DB_PASSWORD", "REDIS_PASSWORD"]
    # PEM keys (ACCESS_PRIVATE_KEY) are excluded — they do not match the
    # symmetric-secret regex and must not be validated against it.
    secret_keys: ClassVar[List[str]] = [
        "ACCESS_SECRET_KEY",
        "REFRESH_SECRET_KEY",
    ]

    # ── Core ──────────────────────────────────────────────────────────────────
    DOMAIN: str = Field(..., pattern=ValidationConstants.HOST_REGEX.pattern)
    ENVIRONMENT: Literal["local", "development", "staging", "production"]
    API_PREFIX: str = Field(..., pattern=ValidationConstants.URL_PATH_STR_REGEX.pattern)
    SET_OPEN_API: bool = True
    SET_DOCS: bool = True
    SET_REDOC: bool = True
    PROJECT_NAME: str = Field(..., pattern=ValidationConstants.KEY_REGEX.pattern)
    STACK_NAME: str = Field(..., pattern=ValidationConstants.SLUG_REGEX.pattern)
    STATIC_BASE_PATH: str = Field(
        ..., pattern=ValidationConstants.FILE_PATH_REGEX.pattern
    )
    TEMPLATES_BASE_PATH: str = Field(
        ..., pattern=ValidationConstants.FILE_PATH_REGEX.pattern
    )

    # ── CORS / Frontend ───────────────────────────────────────────────────────
    BACKEND_HOST: HttpUrl
    FRONTEND_HOST: HttpUrl
    EXTENSION_ID: str = ""
    BACKEND_CORS_ORIGINS: str

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def validate_cors_origins(cls, v: str) -> str:
        """Validate each origin in the comma-separated list."""
        if not isinstance(v, str):
            raise ValueError("BACKEND_CORS_ORIGINS must be a comma-separated string.")
        parse_cors(v)
        return v

    @computed_field
    @property
    def ALLOWED_ORIGINS(self) -> List[str]:
        """Combine BACKEND_CORS_ORIGINS with FRONTEND_HOST."""
        frontend = str(self.FRONTEND_HOST).rstrip("/")
        origins = parse_cors(self.BACKEND_CORS_ORIGINS)
        if frontend not in origins:
            origins.append(frontend)
        return origins

    # ── Security / Tokens ─────────────────────────────────────────────────────
    # Deprecated: no longer used for token signing. Kept for backward compat.
    SECRET_KEY: Optional[SecretStr] = None
    # HS256: set ACCESS_SECRET_KEY (symmetric).
    # RS256/ES256: set ACCESS_PRIVATE_KEY (signing, auth service only) and
    #              ACCESS_PUBLIC_KEY (validation, all services).
    ACCESS_SECRET_KEY: Optional[SecretStr] = None
    ACCESS_PRIVATE_KEY: Optional[SecretStr] = None  # PEM RSA/EC private key
    ACCESS_PUBLIC_KEY: Optional[str] = None  # PEM RSA/EC public key
    REFRESH_SECRET_KEY: SecretStr  # Always HS256 (internal)
    # Deprecated: set ACCESS_TOKEN_ALGORITHM / REFRESH_TOKEN_ALGORITHM instead.
    # Kept as a fallback: if the per-type fields are not explicitly set they
    # inherit this value via _sync_token_algorithms.
    TOKEN_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_ALGORITHM: str = "HS256"
    REFRESH_TOKEN_ALGORITHM: str = "HS256"
    # Controls session persistence and JTI blacklisting strategy:
    #   stateless — pure JWT, no Redis or DB session required
    #   hybrid    — access tokens are stateless; refresh JTIs tracked in Redis
    #   stateful  — full Redis blacklist + DB session (default, current behaviour)
    TOKEN_MODE: Literal["stateless", "stateful", "hybrid"] = "stateful"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 120
    REFRESH_TOKEN_COOKIE_EXPIRE_SECONDS: int = 3600
    # When set, issued tokens embed this as the `iss` claim and validation
    # enforces a match.  Both services must agree on this value.
    TOKEN_ISSUER: Optional[str] = None
    # When set, issued tokens embed this as the `aud` claim.  Set to the
    # consuming service's URL so tokens issued for a different audience are
    # rejected.  Both services must agree on this value.
    TOKEN_AUDIENCE: Optional[str] = None

    SENTRY_DSN: Optional[HttpUrl] = None
    SELECTED_DB: Literal["Mysql", "Postgres"] = "Mysql"

    # ── Database ─────────────────────────────────────────────────────────────
    DB_ENGINE: str = "InnoDB"
    DB_CHARSET: str = "utf8mb4"
    DB_HOST: str = Field(..., pattern=ValidationConstants.HOST_REGEX.pattern)
    DB_PORT: int = Field(..., ge=1, le=65535)
    DB_DATABASE: str = Field(..., pattern=ValidationConstants.KEY_REGEX.pattern)
    DB_USER: str = Field(..., pattern=ValidationConstants.KEY_REGEX.pattern)
    DB_PASSWORD: SecretStr

    @staticmethod
    def _validate_password(field_name: str, secret: SecretStr) -> SecretStr:
        raw = secret.get_secret_value()
        if not ValidationConstants.PASSWORD_REGEX.match(raw):
            raise ValueError(
                f"{field_name} must be at least 8 characters and include "
                "upper, lower, digit, and special character."
            )
        return secret

    @computed_field
    @property
    def SQLALCHEMY_DATABASE_URI(self) -> str:
        """Build the SQLAlchemy connection URI for the selected database."""
        validated_password = self._validate_password("DB_PASSWORD", self.DB_PASSWORD)
        encoded_password = quote_plus(validated_password.get_secret_value())
        credentials = (
            f"{self.DB_USER}:{encoded_password}@"
            f"{self.DB_HOST}:{self.DB_PORT}/{self.DB_DATABASE}"
        )
        if self.SELECTED_DB == "Postgres":
            return f"postgresql+psycopg2://{credentials}"
        return f"mysql+pymysql://{credentials}"

    # ── Redis ─────────────────────────────────────────────────────────────────
    REDIS_HOST: str = Field(..., pattern=ValidationConstants.HOST_REGEX.pattern)
    REDIS_PORT: int
    REDIS_USER: str = Field(..., pattern=ValidationConstants.KEY_REGEX.pattern)
    REDIS_PASSWORD: SecretStr

    # ── Email (optional) ──────────────────────────────────────────────────────
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    EMAILS_FROM_EMAIL: Optional[EmailStr] = None
    EMAILS_FROM_NAME: Optional[str] = None
    EMAIL_TEST_USER: EmailStr = "test@example.com"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def emails_enabled(self) -> bool:
        """True when SMTP_HOST and EMAILS_FROM_EMAIL are both configured."""
        return bool(self.SMTP_HOST and self.EMAILS_FROM_EMAIL)

    # ── Validators ────────────────────────────────────────────────────────────

    @model_validator(mode="after")
    def _sync_token_algorithms(self) -> "CommonSettings":
        """Propagate TOKEN_ALGORITHM to per-type fields when not overridden."""
        if self.TOKEN_ALGORITHM != "HS256":
            if self.ACCESS_TOKEN_ALGORITHM == "HS256":
                self.ACCESS_TOKEN_ALGORITHM = self.TOKEN_ALGORITHM
            if self.REFRESH_TOKEN_ALGORITHM == "HS256":
                self.REFRESH_TOKEN_ALGORITHM = self.TOKEN_ALGORITHM
        return self

    @model_validator(mode="after")
    def _validate_key_material(self) -> "CommonSettings":
        """Ensure the right key material is present for the configured algorithm."""
        algo = self.ACCESS_TOKEN_ALGORITHM
        if algo == "HS256":
            if not self.ACCESS_SECRET_KEY:
                raise ValueError(
                    "ACCESS_SECRET_KEY is required when ACCESS_TOKEN_ALGORITHM=HS256"
                )
        else:
            if not self.ACCESS_PUBLIC_KEY:
                raise ValueError(
                    f"ACCESS_PUBLIC_KEY (PEM) is required when "
                    f"ACCESS_TOKEN_ALGORITHM={algo}. "
                    "Consumer services need only the public key; the auth service "
                    "additionally needs ACCESS_PRIVATE_KEY to sign tokens."
                )
        return self

    @model_validator(mode="after")
    def validate_sensitive_fields(self) -> "CommonSettings":
        """Enforce strength requirements on passwords and secret keys."""
        for name in self.secret_fields:
            secret = getattr(self, name, None)
            if not isinstance(secret, SecretStr):
                continue
            raw = secret.get_secret_value().strip()
            if name in self.passwords:
                if not ValidationConstants.PASSWORD_REGEX.match(raw):
                    raise ValueError(
                        f"{name} must be a strong password: "
                        "8+ chars, upper, lower, digit, special char."
                    )
            if name in self.secret_keys:
                if not ValidationConstants.SECRET_KEY_REGEX.match(raw):
                    raise ValueError(f"{name} must be a valid secret key.")
        return self

    @model_validator(mode="after")
    def enforce_secure_and_required_values(self) -> "CommonSettings":
        """Ensure required fields are present and secrets are not defaults."""
        insecure_default = "changethis"
        for field_item in self.required_fields:
            val = getattr(self, field_item, None)
            if not val or (isinstance(val, str) and not val.strip()):
                raise ValueError(f"'{field_item}' must be provided and not be empty.")
        for field_item in self.secret_fields:
            val = getattr(self, field_item, None)
            if val is None:
                continue
            raw_val = (
                val.get_secret_value() if hasattr(val, "get_secret_value") else val
            )
            if isinstance(raw_val, str) and raw_val.strip().lower() == insecure_default:
                raise ValueError(
                    f"Insecure default value for '{field_item}'. "
                    "Set a strong unique value."
                )
        return self
