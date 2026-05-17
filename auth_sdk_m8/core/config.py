"""CommonSettings — base pydantic-settings class for m8 microservices.

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
    PrivateAttr,
    SecretStr,
    computed_field,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings

from auth_sdk_m8.core.config_health import check_config_health as check_config_health
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
        """Return the value of the environment variable *key*, or None."""
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
    """Source priority: init kwargs > .env file > env vars > Vault (prod/staging).

    .. deprecated::
        Pass via ``model_config`` does not work with pydantic-settings ≥ 2.x.
        Vault injection is now handled by the ``settings_customise_sources``
        classmethod on :class:`CommonSettings` — no action needed in subclasses.
    """
    sources: list[Any] = [init_settings, file_secret_settings, env_settings]
    env = getenv("ENVIRONMENT", "").lower()
    secret_provider = getenv("SECRET_PROVIDER", "").lower()

    if env in {"production", "staging"} and secret_provider == "vault":  # nosec B105 - provider name, not a password
        vault_addr = getenv("VAULT_ADDR")
        vault_token = getenv("VAULT_TOKEN")
        token_file = "/run/secrets/vault_token"  # nosec B105 - Docker secrets mount path, not a hardcoded password
        if not vault_token and Path(token_file).is_file():
            vault_token = Path(token_file).read_text(encoding="utf-8").strip()
        if vault_addr and vault_token:
            provider = VaultProvider(vault_addr, vault_token)

            def _vault_source(_settings: Any = None) -> Dict[str, Any]:
                return {
                    key: val
                    for key in REQUIRE_UPDATE_FIELDS
                    if (val := provider.get(key)) is not None
                }

            sources.append(_vault_source)

    return tuple(sources)


def _build_vault_source(vault_addr: str, vault_token: str) -> Any:
    """Return a pydantic-settings callable source that reads secrets from Vault."""
    provider = VaultProvider(vault_addr, vault_token)

    def _vault_source(_settings: Any = None) -> Dict[str, Any]:
        return {
            key: val
            for key in REQUIRE_UPDATE_FIELDS
            if (val := provider.get(key)) is not None
        }

    return _vault_source


def parse_cors(value: str) -> List[str]:
    """Parse a comma-separated CORS origins string into a validated list.

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


def _assert_key_strength(pem: str, algo: str, *, is_private: bool) -> None:
    """Raise ValueError if an asymmetric key fails minimum strength requirements.

    Args:
        pem: PEM-encoded key material (private or public).
        algo: JWT algorithm the key will be used with (``RS256``, ``ES256``).
        is_private: ``True`` when *pem* encodes a private key.

    Raises:
        ValueError: Key cannot be parsed, wrong type, or is too weak.
    """
    from cryptography.hazmat.primitives.asymmetric import ec, rsa  # noqa: PLC0415
    from cryptography.hazmat.primitives.serialization import (  # noqa: PLC0415
        load_pem_private_key,
        load_pem_public_key,
    )

    encoded = pem.encode()
    try:
        key: Any = (
            load_pem_private_key(encoded, password=None)
            if is_private
            else load_pem_public_key(encoded)
        )
    except Exception as exc:
        raise ValueError(f"Cannot parse PEM key material: {exc}") from exc

    if algo == "RS256":
        if not isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
            raise ValueError(f"RS256 requires an RSA key; got {type(key).__name__}")
        if key.key_size < 2048:
            raise ValueError(
                f"RS256 requires a minimum 2048-bit RSA key; "
                f"loaded key is {key.key_size} bits"
            )
    elif algo == "ES256":
        if not isinstance(key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)):
            raise ValueError(f"ES256 requires an EC key; got {type(key).__name__}")
        from cryptography.hazmat.primitives.asymmetric.ec import (  # noqa: PLC0415
            SECP256R1,
        )

        if not isinstance(key.curve, SECP256R1):
            raise ValueError(
                f"ES256 requires a P-256 (secp256r1) EC curve; "
                f"loaded key uses {type(key.curve).__name__}"
            )


class CommonSettings(BaseSettings):
    """Base settings class for all m8 microservices.

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
        "REFRESH_SECRET_KEY",
        "DB_PASSWORD",
        "REDIS_PASSWORD",
    ]
    passwords: ClassVar[List[str]] = ["DB_PASSWORD", "REDIS_PASSWORD"]
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
    # RS256/ES256: provide key files via ACCESS_PRIVATE_KEY_FILE / ACCESS_PUBLIC_KEY_FILE
    # (Docker/K8s volume mount) or ACCESS_PUBLIC_KEY_FILE + JWKS_URI for consumers.
    ACCESS_SECRET_KEY: Optional[SecretStr] = None
    # File paths — the only supported way to supply RSA/EC key material.
    # Mount ./keys:/opt/keys:ro and set these to the container paths.
    ACCESS_PRIVATE_KEY_FILE: Optional[str] = None
    ACCESS_PUBLIC_KEY_FILE: Optional[str] = None
    # Internal — populated by _load_pem_files from the *_FILE paths above.
    # Not settable via environment variable.
    _access_private_key: Optional[SecretStr] = PrivateAttr(default=None)
    _access_public_key: Optional[str] = PrivateAttr(default=None)

    @property
    def ACCESS_PRIVATE_KEY(self) -> Optional[SecretStr]:
        """RSA/EC private key loaded from ACCESS_PRIVATE_KEY_FILE."""
        return self._access_private_key

    @property
    def ACCESS_PUBLIC_KEY(self) -> Optional[str]:
        """RSA/EC public key loaded from ACCESS_PUBLIC_KEY_FILE."""
        return self._access_public_key

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

    @computed_field
    @property
    def is_stateless(self) -> bool:
        """True when TOKEN_MODE is ``stateless`` — no Redis or DB session needed."""
        return self.TOKEN_MODE == "stateless"  # nosec B105 - token mode name, not a password

    @computed_field
    @property
    def is_stateful(self) -> bool:
        """True when TOKEN_MODE is ``stateful`` — full Redis blacklist + DB session."""
        return self.TOKEN_MODE == "stateful"  # nosec B105 - token mode name, not a password

    @computed_field
    @property
    def requires_redis(self) -> bool:
        """True when TOKEN_MODE requires Redis (``stateful`` or ``hybrid``)."""
        return self.TOKEN_MODE in {"stateful", "hybrid"}

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
    # RS256/ES256 only — key ID embedded in the JWT `kid` header and served
    # in /.well-known/jwks.json.  If unset the auth service derives a stable
    # fingerprint from the public key.  Consumer services do not need to set
    # this; they receive it via the JWKS document.
    ACCESS_KEY_ID: Optional[str] = None
    # Consumer services: full URL of the auth service JWKS endpoint.
    # When set, build_access_validator() uses JwksKeyResolver instead of a
    # static public key — enabling zero-downtime key rotation.
    # Example: "https://auth.example.com/user/.well-known/jwks.json"
    JWKS_URI: Optional[str] = None
    JWKS_CACHE_TTL_SECONDS: int = 300
    # Declares whether this process issues tokens (signs and serves JWKS) or
    # only validates tokens from another issuer.  Drives role-aware enforcement
    # in check_config_health(): consumers must not hold private keys; issuers
    # with asymmetric algorithms must hold a private key.
    AUTH_SERVICE_ROLE: Literal["issuer", "consumer"] = "issuer"

    # When true, warnings that indicate production security risks become fatal
    # errors, aborting startup.  Recommended for staging/production CI gates.
    STRICT_PRODUCTION_MODE: bool = False
    # Controls the Secure flag on session cookies (Starlette SessionMiddleware
    # https_only parameter).  Defaults True; only set False in local/dev.
    SESSION_COOKIE_SECURE: bool = True

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
        if self.TOKEN_ALGORITHM != "HS256":  # nosec B105 - JWT algorithm name, not a password
            if self.ACCESS_TOKEN_ALGORITHM == "HS256":  # nosec B105
                self.ACCESS_TOKEN_ALGORITHM = self.TOKEN_ALGORITHM
            if self.REFRESH_TOKEN_ALGORITHM == "HS256":  # nosec B105
                self.REFRESH_TOKEN_ALGORITHM = self.TOKEN_ALGORITHM
        return self

    @model_validator(mode="after")
    def _load_pem_files(self) -> "CommonSettings":
        """Load PEM content from *_FILE paths into private attributes."""
        if self.ACCESS_PRIVATE_KEY_FILE:
            path = Path(self.ACCESS_PRIVATE_KEY_FILE)
            if not path.is_file():
                raise ValueError(f"ACCESS_PRIVATE_KEY_FILE not found: {path}")
            self._access_private_key = SecretStr(path.read_text().strip())
        if self.ACCESS_PUBLIC_KEY_FILE:
            path = Path(self.ACCESS_PUBLIC_KEY_FILE)
            if not path.is_file():
                raise ValueError(f"ACCESS_PUBLIC_KEY_FILE not found: {path}")
            self._access_public_key = path.read_text().strip()
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
            # Consumers use JWKS_URI (preferred) or ACCESS_PUBLIC_KEY_FILE.
            # The auth service needs ACCESS_PRIVATE_KEY_FILE + ACCESS_PUBLIC_KEY_FILE.
            if not self.ACCESS_PUBLIC_KEY and not self.JWKS_URI:
                raise ValueError(
                    f"ACCESS_TOKEN_ALGORITHM={algo} requires a public key source. "
                    "Auth service: set ACCESS_PRIVATE_KEY_FILE and ACCESS_PUBLIC_KEY_FILE. "
                    "Consumer: set JWKS_URI (preferred) or ACCESS_PUBLIC_KEY_FILE."
                )
        return self

    @model_validator(mode="after")
    def _validate_key_strength(self) -> "CommonSettings":
        """Enforce minimum cryptographic strength for asymmetric key material."""
        algo = self.ACCESS_TOKEN_ALGORITHM
        if algo == "HS256":
            return self
        if self._access_private_key:
            _assert_key_strength(
                self._access_private_key.get_secret_value(), algo, is_private=True
            )
        elif self._access_public_key:
            _assert_key_strength(self._access_public_key, algo, is_private=False)
        # Consumer with only JWKS_URI — no local key to validate here.
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

    @classmethod
    def settings_customise_sources(  # type: ignore[override]
        cls,
        _settings_cls: "type[CommonSettings]",
        init_settings: Any,
        env_settings: Any,
        dotenv_settings: Any,
        file_secret_settings: Any,
    ) -> "Tuple[Any, ...]":
        """Source priority: init kwargs > .env file > env vars > Docker secrets > Vault."""
        sources: list[Any] = [
            init_settings,
            dotenv_settings,
            env_settings,
            file_secret_settings,
        ]
        env = getenv("ENVIRONMENT", "").lower()
        secret_provider = getenv("SECRET_PROVIDER", "").lower()
        if env in {"production", "staging"} and secret_provider == "vault":  # nosec B105
            vault_addr = getenv("VAULT_ADDR")
            vault_token = getenv("VAULT_TOKEN")
            token_file = "/run/secrets/vault_token"  # nosec B105
            if not vault_token and Path(token_file).is_file():
                vault_token = Path(token_file).read_text(encoding="utf-8").strip()
            if vault_addr and vault_token:
                sources.append(_build_vault_source(vault_addr, vault_token))
        return tuple(sources)
