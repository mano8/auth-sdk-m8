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
            import hvac  # type: ignore[import-untyped]  # noqa: PLC0415
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


def _read_secret_file(path_str: str, field_name: str) -> str:
    """Return the stripped contents of a `*_FILE` secret mount.

    Args:
        path_str: Filesystem path taken from the ``<FIELD>_FILE`` env var.
        field_name: Owning settings field, used only for error messages.

    Raises:
        ValueError: The path does not point at a readable file (fail-closed —
            a missing secret file is a deployment misconfiguration, never a
            silent fallback to a plaintext value).
    """
    path = Path(path_str)
    if not path.is_file():
        raise ValueError(
            f"{field_name}_FILE points to a missing file: {path}. "
            "Mount the secret file or unset the *_FILE variable."
        )
    return path.read_text(encoding="utf-8").strip()


def _build_file_secret_source(settings_cls: type[BaseSettings]) -> Any:
    """Return a settings source implementing the Docker/K8s `*_FILE` convention.

    For any model field ``FOO``, if the environment defines ``FOO_FILE`` pointing
    at a readable file, the file's stripped contents become the value of ``FOO``.
    This lets the production overlay mount secrets under ``/run/secrets/*`` (Docker
    secrets / SOPS / Vault agent / K8s) instead of inlining plaintext values into
    env files. Field names are resolved once from the concrete settings subclass,
    so every secret declared by a service is covered without an explicit allowlist.
    File contents are never logged.
    """
    field_names = frozenset(settings_cls.model_fields)

    def _file_secret_source(_settings: Any = None) -> Dict[str, Any]:
        values: Dict[str, Any] = {}
        for field_name in field_names:
            path_str = getenv(f"{field_name}_FILE")
            if path_str:
                values[field_name] = _read_secret_file(path_str, field_name)
        return values

    return _file_secret_source


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
    # Published dev/test keys from this repo's own examples and test suite.
    # Any of these appearing in a production config is a copy-paste mistake.
    _dev_placeholder_keys: ClassVar[frozenset[str]] = frozenset(
        {
            # conftest.py VALID_KEY / WRONG_KEY (public in git, pass SECRET_KEY_REGEX)
            "Abcdef-1234_XYZ-abcdef-ghijkl-mnopqr-stuvwx",
            "Zyxwvu-9876_ABC-zyxwvu-tsrqpo-nmlkji-hgfedc",
        }
    )

    # ── Core ──────────────────────────────────────────────────────────────────
    DOMAIN: str = Field(..., pattern=ValidationConstants.HOST_REGEX.pattern)
    ENVIRONMENT: Literal["local", "development", "staging", "production"]
    API_PREFIX: str = Field(..., pattern=ValidationConstants.URL_PATH_STR_REGEX.pattern)
    SET_OPEN_API: bool = True
    SET_DOCS: bool = True
    SET_REDOC: bool = True
    # Explicit opt-in to serve docs endpoints in production (ENVIRONMENT==
    # "production" or STRICT_PRODUCTION_MODE).  Default False (secure-by-default);
    # set True for public/open-source APIs that intentionally publish live docs.
    SERVE_DOCS_IN_PRODUCTION: bool = False
    PROJECT_NAME: str = Field(..., pattern=ValidationConstants.KEY_REGEX.pattern)
    STACK_NAME: str = Field(..., pattern=ValidationConstants.SLUG_REGEX.pattern)

    # ── CORS / Frontend ───────────────────────────────────────────────────────
    BACKEND_HOST: HttpUrl
    FRONTEND_HOST: HttpUrl
    BACKEND_CORS_ORIGINS: str

    # ── OAuth redirect policy ─────────────────────────────────────────────────
    # URI schemes accepted as redirect_target at /google-api/login-url/.
    # Default: chrome-extension:// only. Comma-separated for multiple clients.
    # Web schemes (http://, https://) must be explicitly listed and paired with
    # OAUTH_ALLOWED_REDIRECT_PREFIXES by the auth service before use.
    OAUTH_ALLOWED_REDIRECT_SCHEMES: List[str] = ["chrome-extension://"]

    @field_validator("OAUTH_ALLOWED_REDIRECT_SCHEMES", mode="before")
    @classmethod
    def parse_redirect_schemes(cls, v: object) -> List[str]:
        """Parse comma-separated redirect schemes from env."""
        if isinstance(v, str):
            return [s.strip() for s in v.split(",") if s.strip()]
        return list(v) if v else ["chrome-extension://"]  # type: ignore[call-overload]

    # Optional: restrict to known extension IDs (empty = open public-client model).
    # Set to chrome-extension://abc123.../ to pin specific extensions.
    # See README: redirect URI is a delivery channel, not an identity binding mechanism.
    OAUTH_ALLOWED_REDIRECT_PREFIXES: List[str] = []

    @field_validator("OAUTH_ALLOWED_REDIRECT_PREFIXES", mode="before")
    @classmethod
    def parse_redirect_prefixes(cls, v: object) -> List[str]:
        """Parse comma-separated redirect prefix allowlist from env."""
        if isinstance(v, str):
            return [s.strip() for s in v.split(",") if s.strip()]
        return list(v) if v else []  # type: ignore[call-overload]

    # CORS scheme allowlist — required for extension fetch() calls.
    # Extension sends Origin: chrome-extension://{id}. Standard CORSMiddleware
    # only matches exact origins — this enables scheme-level matching via regex.
    # Only chrome-extension:// is supported; custom schemes require custom impl.
    CORS_ALLOWED_ORIGIN_SCHEMES: List[str] = []

    # ── Trusted hosts ─────────────────────────────────────────────────────────
    # Allowlist of Host header values accepted by Starlette's
    # TrustedHostMiddleware.  None (default) disables host checking — operators
    # must set this in production.  Comma-separated when sourced from env.
    # Examples: "example.com,www.example.com" (prod), "localhost" (local),
    # "testserver" (test client).
    ALLOWED_HOSTS: Optional[List[str]] = None

    @field_validator("ALLOWED_HOSTS", mode="before")
    @classmethod
    def parse_allowed_hosts(cls, v: object) -> Optional[List[str]]:
        """Parse comma-separated allowed hosts from env."""
        if v is None:
            return None
        if isinstance(v, str):
            hosts = [h.strip() for h in v.split(",") if h.strip()]
            return hosts if hosts else None
        return list(v) if v else None  # type: ignore[call-overload]

    @field_validator("CORS_ALLOWED_ORIGIN_SCHEMES", mode="before")
    @classmethod
    def parse_cors_origin_schemes(cls, v: object) -> List[str]:
        """Parse comma-separated CORS origin scheme allowlist from env."""
        if isinstance(v, str):
            return [s.strip() for s in v.split(",") if s.strip()]
        return list(v) if v else []  # type: ignore[call-overload]

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def validate_cors_origins(cls, v: str) -> str:
        """Validate each origin in the comma-separated list."""
        if not isinstance(v, str):
            raise ValueError("BACKEND_CORS_ORIGINS must be a comma-separated string.")
        parse_cors(v)
        return v

    @computed_field  # type: ignore[prop-decorator]
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
    REFRESH_SECRET_KEY_OLD: Optional[SecretStr] = None  # Set during key rotation
    # Deprecated: set ACCESS_TOKEN_ALGORITHM instead.  Kept as a fallback: when
    # ACCESS_TOKEN_ALGORITHM is left at its default it inherits this value via
    # _sync_token_algorithms.  Never propagated to REFRESH_TOKEN_ALGORITHM.
    #
    # SECURE-BY-DEFAULT (BREAKING in 1.0.0): the default access-token algorithm
    # is RS256 (asymmetric / JWKS).  HS256 (shared secret) is still fully
    # supported but must be opted into explicitly by setting
    # ACCESS_TOKEN_ALGORITHM=HS256 (or TOKEN_ALGORITHM=HS256) and providing
    # ACCESS_SECRET_KEY.  Refresh tokens are internal and remain HS256 always.
    TOKEN_ALGORITHM: str = "RS256"
    ACCESS_TOKEN_ALGORITHM: str = "RS256"
    REFRESH_TOKEN_ALGORITHM: str = "HS256"
    # Controls session persistence and JTI blacklisting strategy:
    #   stateless — pure JWT, no Redis or DB session required
    #   hybrid    — access tokens are stateless; refresh JTIs tracked in Redis
    #   stateful  — full Redis blacklist + DB session (default, current behaviour)
    TOKEN_MODE: Literal["stateless", "stateful", "hybrid"] = "stateful"

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_stateless(self) -> bool:
        """True when TOKEN_MODE is ``stateless`` — no Redis or DB session needed."""
        return self.TOKEN_MODE == "stateless"  # nosec B105 - token mode name, not a password

    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_stateful(self) -> bool:
        """True when TOKEN_MODE is ``stateful`` — full Redis blacklist + DB session."""
        return self.TOKEN_MODE == "stateful"  # nosec B105 - token mode name, not a password

    @computed_field  # type: ignore[prop-decorator]
    @property
    def requires_redis(self) -> bool:
        """True when THIS service owns and manages a Redis instance.

        Only issuers in hybrid/stateful mode need local Redis:
          hybrid issuer  → refresh token allowlist
          stateful issuer → access token blacklist + refresh allowlist

        Consumer services never need local auth Redis in any mode:
          stateless/hybrid consumer → access tokens are stateless, no blacklist
          stateful consumer         → revocation delegated via HTTP introspection
        """
        return self.AUTH_SERVICE_ROLE == "issuer" and not self.is_stateless

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
    # SECURE-BY-DEFAULT (BREAKING in 1.0.0): strict access-token validation is
    # ON by default.  The SDK's validation wiring (build_access_validator)
    # enforces both `iss` and `aud` binding, and startup REQUIRES TOKEN_ISSUER
    # and TOKEN_AUDIENCE to be set (fail-closed at boot).  Opt out only for
    # single-service / dev deployments that do not need cross-service token
    # boundaries by setting TOKEN_STRICT_VALIDATION=false — validation then
    # falls back to the permissive profile (iss/aud enforced only when set).
    TOKEN_STRICT_VALIDATION: bool = True
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
    # Break-glass flag: allow plain http:// on inter-service URL fields (JWKS_URI,
    # INTROSPECTION_URL) even in staging/production.  Intended only for trusted
    # single-host Docker deployments where all traffic stays on a private bridge
    # network.  Defaults False: http:// URLs warn in prod and are fatal under
    # STRICT unless this opt-in is set; setting it opts the runtime health check
    # out of the http:// warning.  Ignored in local/dev (http:// always allowed).
    ALLOW_INTERNAL_HTTP: bool = False
    # Controls the Secure flag on session cookies (Starlette SessionMiddleware
    # https_only parameter).  Defaults True; only set False in local/dev.
    SESSION_COOKIE_SECURE: bool = True

    # ── Response security headers (tiered) ─────────────────────────────────────
    # Wired by auth_sdk_m8.security.headers.add_security_headers_middleware
    # (shared by consumer services via fastapi_m8.create_app and by fa-auth's own
    # app). Three tiers:
    #   1. Always-on: X-Content-Type-Options, X-Frame-Options.
    #   2. Production-gated (ENVIRONMENT=="production" or STRICT_PRODUCTION_MODE):
    #      Referrer-Policy, Permissions-Policy.
    #   3. Express opt-in only (HSTS_ENABLED / CONTENT_SECURITY_POLICY_ENABLED):
    #      HSTS and CSP. These are browser-persisted and hard to reverse, so they
    #      are NEVER inferred from the production gate and NEVER emitted when
    #      ENVIRONMENT=="local" even if opted in.
    # Set SECURITY_HEADERS_ENABLED=false to suppress the whole layer.
    SECURITY_HEADERS_ENABLED: bool = True
    # HSTS — express opt-in. Browser-persisted: enabling it on a host reached over
    # plain HTTP (or on localhost) poisons the HTTPS cache for HSTS_MAX_AGE
    # seconds. Only enable behind a TLS-terminating proxy. Never emitted locally.
    HSTS_ENABLED: bool = False
    # HSTS max-age in seconds (0 also disables the header). Only applies when
    # HSTS_ENABLED is True.
    HSTS_MAX_AGE: int = 31536000  # 1 year
    HSTS_INCLUDE_SUBDOMAINS: bool = True
    # CSP — express opt-in. Can silently break pages/tooling, so off by default.
    CONTENT_SECURITY_POLICY_ENABLED: bool = False
    # Content-Security-Policy value used when CONTENT_SECURITY_POLICY_ENABLED is
    # True. None → a tight default suitable for a JSON API (`default-src 'none';
    # frame-ancestors 'none'; base-uri 'none'; form-action 'none'`). Override for
    # services that serve HTML.
    CONTENT_SECURITY_POLICY: Optional[str] = None
    REFERRER_POLICY: str = "strict-origin-when-cross-origin"
    PERMISSIONS_POLICY: str = (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"
    )

    # ── Event bus signing (Redis Pub/Sub) ─────────────────────────────────────
    # SECURE-BY-DEFAULT (BREAKING in 1.0.0): event-bus payloads are HMAC-SHA256
    # signed and consumers reject unsigned/forged events.  Pass
    # EVENT_SIGNING_KEY to EventBus / EventPublisher / EventSubscriber.
    #   EVENT_SIGNING_ENABLED          — master switch (default True).  When
    #     True, EVENT_SIGNING_KEY is required at startup (fail-closed at boot).
    #     Set False to disable signing entirely (opt-out).
    #   EVENT_SIGNING_KEY              — shared HMAC secret; all publishers and
    #     subscribers on a channel must share it.  Must satisfy SECRET_KEY_REGEX.
    #   EVENT_SIGNING_ACCEPT_UNSIGNED  — transitional rollout flag.  When True,
    #     consumers accept BOTH signed and unsigned messages (still rejecting
    #     forged signatures) so a mixed fleet can migrate.  Default False
    #     (signed-required); flip back to False once every publisher signs.
    EVENT_SIGNING_ENABLED: bool = True
    EVENT_SIGNING_KEY: Optional[SecretStr] = None
    EVENT_SIGNING_ACCEPT_UNSIGNED: bool = False

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

    @computed_field  # type: ignore[prop-decorator]
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
    # Optional for consumer services — only issuers in hybrid/stateful mode
    # need local Redis.  Validated by _enforce_redis_for_issuers.
    REDIS_HOST: Optional[str] = Field(
        default=None, pattern=ValidationConstants.HOST_REGEX.pattern
    )
    REDIS_PORT: Optional[int] = None
    REDIS_USER: Optional[str] = Field(
        default=None, pattern=ValidationConstants.KEY_REGEX.pattern
    )
    REDIS_PASSWORD: Optional[SecretStr] = None
    REDIS_SSL: bool = False
    REDIS_SSL_CA: Optional[str] = None
    REDIS_SSL_CERT: Optional[str] = None
    REDIS_SSL_KEY: Optional[str] = None

    # ── Rate limiting ─────────────────────────────────────────────────────────
    LOGIN_RATE_LIMIT_REQUESTS: int = Field(5, ge=1, le=1000)
    LOGIN_RATE_LIMIT_WINDOW_MINUTES: int = Field(15, ge=1, le=1440)
    REFRESH_RATE_LIMIT_REQUESTS: int = Field(10, ge=1, le=1000)
    REFRESH_RATE_LIMIT_WINDOW_MINUTES: int = Field(5, ge=1, le=1440)

    # ── Auth degradation policy ───────────────────────────────────────────────
    # Controls service behaviour when Redis is unavailable for each security
    # control.  fail_open: allow through.  fail_closed: return 503.
    # AUTH_STRICT_MODE=true overrides all per-control modes to fail_closed.
    AUTH_STRICT_MODE: bool = False
    REFRESH_VALIDATION_FAILURE_MODE: Literal["fail_open", "fail_closed"] = "fail_closed"
    SESSION_WRITE_FAILURE_MODE: Literal["fail_open", "fail_closed"] = "fail_closed"
    RATE_LIMIT_FAILURE_MODE: Literal["fail_open", "fail_closed"] = "fail_open"
    ACCESS_REVOCATION_FAILURE_MODE: Literal["fail_open", "fail_closed"] = "fail_closed"

    def effective_failure_mode(
        self,
        control: Literal[
            "refresh_validation", "session_write", "rate_limit", "access_revocation"
        ],
    ) -> Literal["fail_open", "fail_closed"]:
        """Return the effective failure mode for *control*, respecting AUTH_STRICT_MODE."""
        if self.AUTH_STRICT_MODE:
            return "fail_closed"
        return {
            "refresh_validation": self.REFRESH_VALIDATION_FAILURE_MODE,
            "session_write": self.SESSION_WRITE_FAILURE_MODE,
            "rate_limit": self.RATE_LIMIT_FAILURE_MODE,
            "access_revocation": self.ACCESS_REVOCATION_FAILURE_MODE,
        }[control]

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

    # ── Docs/OpenAPI gating ───────────────────────────────────────────────────
    # Docs endpoints are gated off in production (ENVIRONMENT=="production" or
    # STRICT_PRODUCTION_MODE=True) regardless of the raw SET_* flags, UNLESS
    # SERVE_DOCS_IN_PRODUCTION=True explicitly opts back in.  Non-production:
    # effective value == configured value (dev DX preserved).

    @property
    def _docs_gated(self) -> bool:
        """True when production hides docs and the operator has not opted in."""
        is_production = self.ENVIRONMENT == "production" or self.STRICT_PRODUCTION_MODE
        return is_production and not self.SERVE_DOCS_IN_PRODUCTION

    @computed_field  # type: ignore[prop-decorator]
    @property
    def effective_set_open_api(self) -> bool:
        """OpenAPI schema enabled unless gated off by production mode."""
        return self.SET_OPEN_API and not self._docs_gated

    @computed_field  # type: ignore[prop-decorator]
    @property
    def effective_set_docs(self) -> bool:
        """Swagger UI enabled unless gated off by production mode."""
        return self.SET_DOCS and not self._docs_gated

    @computed_field  # type: ignore[prop-decorator]
    @property
    def effective_set_redoc(self) -> bool:
        """ReDoc UI enabled unless gated off by production mode."""
        return self.SET_REDOC and not self._docs_gated

    # ── Validators ────────────────────────────────────────────────────────────

    @model_validator(mode="after")
    def _sync_token_algorithms(self) -> "CommonSettings":
        """Seed ACCESS_TOKEN_ALGORITHM from the deprecated TOKEN_ALGORITHM.

        The deprecated ``TOKEN_ALGORITHM`` knob only seeds
        ``ACCESS_TOKEN_ALGORITHM`` when the per-type field is still at its
        default (``RS256``); an explicit ``ACCESS_TOKEN_ALGORITHM`` always wins.
        ``TOKEN_ALGORITHM`` is never propagated to ``REFRESH_TOKEN_ALGORITHM`` —
        refresh tokens are internal and must always use symmetric HS256 signing.
        """
        if (
            self.ACCESS_TOKEN_ALGORITHM == "RS256"  # nosec B105 - default sentinel, not a password
            and self.TOKEN_ALGORITHM != "RS256"  # nosec B105
        ):
            self.ACCESS_TOKEN_ALGORITHM = self.TOKEN_ALGORITHM
        if self.REFRESH_TOKEN_ALGORITHM != "HS256":  # nosec B105
            raise ValueError(
                "REFRESH_TOKEN_ALGORITHM must be HS256. "
                "Refresh tokens are internal and must use symmetric signing."
            )
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
    def _validate_redis_ssl(self) -> "CommonSettings":
        """Enforce Redis TLS configuration consistency."""
        if self.REDIS_SSL and not self.REDIS_SSL_CA:
            raise ValueError("REDIS_SSL_CA is required when REDIS_SSL=true")
        for value, name in [
            (self.REDIS_SSL_CA, "REDIS_SSL_CA"),
            (self.REDIS_SSL_CERT, "REDIS_SSL_CERT"),
            (self.REDIS_SSL_KEY, "REDIS_SSL_KEY"),
        ]:
            if value and not Path(value).is_file():
                raise ValueError(f"{name} file not found: {value}")
        if bool(self.REDIS_SSL_CERT) ^ bool(self.REDIS_SSL_KEY):
            raise ValueError(
                "REDIS_SSL_CERT and REDIS_SSL_KEY must both be set or both unset"
            )
        return self

    @model_validator(mode="after")
    def _enforce_redis_for_issuers(self) -> "CommonSettings":
        """Issuers in hybrid/stateful mode must supply all four REDIS_* fields."""
        if self.AUTH_SERVICE_ROLE == "issuer" and not self.is_stateless:
            missing: list[str] = []
            for name in ("REDIS_HOST", "REDIS_PORT", "REDIS_USER"):
                if not getattr(self, name):  # None or ""
                    missing.append(name)
            # SecretStr is always truthy — must unwrap to check for empty value
            if (
                self.REDIS_PASSWORD is None
                or not self.REDIS_PASSWORD.get_secret_value()
            ):
                missing.append("REDIS_PASSWORD")
            if missing:
                raise ValueError(
                    f"AUTH_SERVICE_ROLE=issuer with TOKEN_MODE={self.TOKEN_MODE} "
                    f"requires all REDIS_* fields; missing or empty: {missing}"
                )
        return self

    @model_validator(mode="after")
    def _enforce_strict_token_binding(self) -> "CommonSettings":
        """Require TOKEN_ISSUER/TOKEN_AUDIENCE when strict validation is on.

        Secure-by-default: with ``TOKEN_STRICT_VALIDATION`` enabled (the
        default) the SDK enforces ``iss``/``aud`` binding, which is meaningless
        without both values configured.  Fail closed at boot with a clear
        message instead of silently issuing/accepting unbound tokens.  Operators
        that genuinely do not need cross-service boundaries opt out via
        ``TOKEN_STRICT_VALIDATION=false``.
        """
        if not self.TOKEN_STRICT_VALIDATION:
            return self
        missing: list[str] = []
        if not (self.TOKEN_ISSUER and self.TOKEN_ISSUER.strip()):
            missing.append("TOKEN_ISSUER")
        if not (self.TOKEN_AUDIENCE and self.TOKEN_AUDIENCE.strip()):
            missing.append("TOKEN_AUDIENCE")
        if missing:
            raise ValueError(
                f"TOKEN_STRICT_VALIDATION=true requires {missing} to be set so "
                "tokens are bound to a specific issuer and audience. "
                "Set both values, or set TOKEN_STRICT_VALIDATION=false for "
                "single-service/dev deployments that do not need cross-service "
                "token boundaries."
            )
        return self

    @model_validator(mode="after")
    def _enforce_event_signing_key(self) -> "CommonSettings":
        """Require a strong EVENT_SIGNING_KEY when event signing is enabled.

        Secure-by-default: event-bus payloads are signed unless
        ``EVENT_SIGNING_ENABLED=false``.  Mirrors ``_enforce_redis_for_issuers``
        — fail closed at boot if the master switch is on but no usable key is
        configured.
        """
        if not self.EVENT_SIGNING_ENABLED:
            return self
        if self.EVENT_SIGNING_KEY is None or not (
            self.EVENT_SIGNING_KEY.get_secret_value().strip()
        ):
            raise ValueError(
                "EVENT_SIGNING_ENABLED=true requires EVENT_SIGNING_KEY to be "
                "set so event-bus payloads can be HMAC-signed. Set a strong "
                "EVENT_SIGNING_KEY, or set EVENT_SIGNING_ENABLED=false to "
                "disable event signing."
            )
        if not ValidationConstants.SECRET_KEY_REGEX.match(
            self.EVENT_SIGNING_KEY.get_secret_value().strip()
        ):
            raise ValueError("EVENT_SIGNING_KEY must be a valid secret key.")
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

    @model_validator(mode="after")
    def _guard_production_placeholder_keys(self) -> "CommonSettings":
        """Reject published dev/test keys in production.

        Any key from ``_dev_placeholder_keys`` that passes strength checks is
        still forbidden in production — it indicates a copy-paste from the
        repo's own examples or test suite rather than a genuine secret.
        Gated on the same ``is_production`` idiom used by ``_docs_gated``.
        """
        is_production = self.ENVIRONMENT == "production" or self.STRICT_PRODUCTION_MODE
        if not is_production:
            return self
        fields_to_check = list(self.secret_keys) + ["EVENT_SIGNING_KEY"]
        for field_name in fields_to_check:
            val = getattr(self, field_name, None)
            if val is None:
                continue
            raw = val.get_secret_value() if hasattr(val, "get_secret_value") else val
            if isinstance(raw, str) and raw.strip() in self._dev_placeholder_keys:
                raise ValueError(
                    f"'{field_name}' contains a well-known development key. "
                    "Generate a unique secret for production."
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
        """Source priority: init kwargs > *_FILE secrets > .env > env > secrets-dir > Vault.

        The ``*_FILE`` source is placed directly below init kwargs so a mounted
        secret file overrides a plaintext value in ``.env`` or the process
        environment — the production overlay sources secrets from files, not from
        inlined env values — while explicit constructor kwargs (tests) still win.
        """
        sources: list[Any] = [
            init_settings,
            _build_file_secret_source(_settings_cls),
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
