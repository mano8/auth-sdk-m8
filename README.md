# auth-sdk-m8

![CI/CD](https://github.com/mano8/auth-sdk-m8/actions/workflows/CI.yaml/badge.svg?branch=main)
[![PyPI version](https://img.shields.io/pypi/v/auth-sdk-m8)](https://pypi.org/project/auth-sdk-m8/)
[![Python](https://img.shields.io/pypi/pyversions/auth-sdk-m8)](https://pypi.org/project/auth-sdk-m8/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/auth-sdk-m8?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/auth-sdk-m8)
[![codecov](https://codecov.io/gh/mano8/auth-sdk-m8/graph/badge.svg?token=TF6OGIHOGF)](https://codecov.io/gh/mano8/auth-sdk-m8)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/8b8e9726b0f8441ea480902ea8910812)](https://app.codacy.com/gh/mano8/auth-sdk-m8/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

Shared authentication schemas, JWT validation, and FastAPI base components for any service that issues or validates JWT tokens. Supports Python 3.11 – 3.14.

Companion SDK to [fa-auth-m8](https://github.com/mano8/fa-auth-m8) — install in any FastAPI service that needs to validate tokens from the fa-auth-m8 authentication service. Provides Pydantic schemas, JWT validation, `CommonSettings`, Redis event bus, and optional Prometheus metrics.

---

## Summary

- [Installation](#installation)
- [Deployment modes](#deployment-modes)
  - [HS256 — symmetric](#hs256--symmetric-simple-single-service-or-monolith)
  - [RS256 — issuer side](#rs256--asymmetric-issuer-side-auth_user_service)
  - [RS256 — consumer JWKS](#rs256--asymmetric-consumer-side-jwks-recommended)
  - [RS256 — consumer offline](#rs256--asymmetric-consumer-offline-static-public-key-file)
  - [ES256 — ECDSA](#es256--ecdsa-drop-in-for-rs256)
- [FastAPI integration](#fastapi-integration)
- [Startup config validation](#startup-config-validation)
- [Service role](#service-role-auth_service_role)
- [Asymmetric key-strength enforcement](#asymmetric-key-strength-enforcement)
- [Strict production mode](#strict-production-mode)
- [Token modes](#token-modes)
- [Chrome extension / native-app OAuth support](#chrome-extension--native-app-oauth-support)
- [Auth degradation policy](#auth-degradation-policy)
- [Issuer / audience enforcement](#issuer--audience-enforcement)
- [Refresh token rotation](#refresh-token-rotation)
- [Observability hooks](#observability-hooks)
- [Prometheus metrics](#prometheus-metrics)
- [Redis event bus](#redis-event-bus)
- [Package layout](#package-layout)
- [Architecture note](#architecture-note)

---

## Installation

```bash
pip install auth-sdk-m8 --upgrade
```

Install only what your service needs:

| Extra | Installs | Use when |
| --- | --- | --- |
| *(none)* | `pydantic`, `email-validator` | schemas only |
| `[security]` | `PyJWT`, `cryptography` | JWT validation |
| `[fastapi]` | `fastapi` | cookie helpers, `BaseController` |
| `[config]` | `pydantic-settings` | `CommonSettings` base class |
| `[redis]` | `redis` | Redis event bus / blacklist |
| `[db]` | `sqlmodel`, `sqlalchemy` | `TimestampMixin`, DB error parsing |
| `[mysql]` | `pymysql` | MySQL driver |
| `[postgres]` | `psycopg2-binary` | PostgreSQL driver |
| `[observability]` | `prometheus-client`, `fastapi` | Prometheus metrics middleware |
| `[all]` | everything | full feature set |

```bash
pip install "auth-sdk-m8[security,fastapi,config,db,mysql]"
```

---

## Deployment modes

| Mode | When to use |
| ---- | ----------- |
| **HS256** | Single service or tight monolith — all services share the same secret |
| **RS256 / ES256 — JWKS** | Multiple independent consumers — each fetches the public key dynamically; recommended for most multi-service setups |
| **RS256 / ES256 — offline** | Air-gapped or embedded deployments where the JWKS endpoint is unreachable |

### HS256 — symmetric (simple, single-service or monolith)

Every service shares the same secret. Simple to set up; not recommended when consumers are
maintained by different teams.

#### .env

```ini
ACCESS_TOKEN_ALGORITHM=HS256
ACCESS_SECRET_KEY=your-strong-secret-key
REFRESH_SECRET_KEY=your-strong-refresh-secret
```

#### Settings

```python
from pathlib import Path
from pydantic_settings import SettingsConfigDict
from auth_sdk_m8.core.config import CommonSettings
from auth_sdk_m8.utils.paths import find_dotenv

class Settings(CommonSettings):
    ENV_FILE_DIR = Path(__file__).resolve().parent
    model_config = SettingsConfigDict(
        env_file=find_dotenv(ENV_FILE_DIR),
        env_file_encoding="utf-8",
    )

settings = Settings()
```

#### Validate a token

```python
from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.security import build_access_validator

validator = build_access_validator(settings)  # create once at module level

try:
    payload = validator.validate_access_token(bearer_token)
    print(payload.sub, payload.role)
except InvalidToken:
    ...
```

---

### RS256 — asymmetric, issuer side (`auth_user_service`)

The auth service holds the private key and publishes a JWKS endpoint.
Consumer services never receive the private key.

#### Generate keys

```bash
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
```

#### docker-compose.yml (auth service)

```yaml
environment:
  ACCESS_TOKEN_ALGORITHM: RS256
  REFRESH_TOKEN_ALGORITHM: HS256
  ACCESS_KEY_ID: main-2026-01
  ACCESS_PRIVATE_KEY_FILE: /opt/keys/private.pem
  ACCESS_PUBLIC_KEY_FILE: /opt/keys/public.pem
volumes:
  - ./keys:/opt/keys:ro
```

#### .env (auth service)

```ini
ACCESS_TOKEN_ALGORITHM=RS256
REFRESH_TOKEN_ALGORITHM=HS256
ACCESS_KEY_ID=main-2026-01
ACCESS_PRIVATE_KEY_FILE=/opt/keys/private.pem
ACCESS_PUBLIC_KEY_FILE=/opt/keys/public.pem
```

> Keys are loaded from disk at startup via `ACCESS_PRIVATE_KEY_FILE` /
> `ACCESS_PUBLIC_KEY_FILE`. Inline PEM strings in env vars are **not supported** —
> newline escaping breaks silently across shells and orchestrators.

---

### RS256 — asymmetric, consumer side (JWKS, recommended)

Consumers fetch the public key dynamically from the auth service JWKS endpoint.
No key files needed. Supports zero-downtime key rotation.

#### .env (consumer service)

```ini
ACCESS_TOKEN_ALGORITHM=RS256
JWKS_URI=http://auth_user_service:8000/user/.well-known/jwks.json
JWKS_CACHE_TTL_SECONDS=300
```

`build_access_validator` automatically uses `JwksKeyResolver` when `JWKS_URI` is set:

```python
# No key file needed — the validator fetches the public key from JWKS.
validator = build_access_validator(settings)
payload = validator.validate_access_token(bearer_token)
```

On an unknown `kid` the resolver refreshes once before raising, so key rotation on the issuer
side is transparent to consumers with no restart required.

---

### RS256 — asymmetric, consumer offline (static public key file)

For air-gapped or embedded deployments where the JWKS endpoint is unreachable.

#### .env (consumer)

```ini
ACCESS_TOKEN_ALGORITHM=RS256
ACCESS_PUBLIC_KEY_FILE=/opt/keys/public.pem
```

Mount only the public key — never the private key — to consumer containers:

```yaml
volumes:
  - ./keys/public.pem:/opt/keys/public.pem:ro
```

### ES256 — ECDSA (drop-in for RS256)

ES256 works identically to RS256 in all three modes above. Replace `RS256` with `ES256` and generate a P-256 EC key pair:

```bash
openssl ecparam -genkey -name prime256v1 -noout -out keys/private.pem
openssl ec -in keys/private.pem -pubout -out keys/public.pem
```

`CommonSettings` enforces P-256 (secp256r1) at startup — other curves are rejected. Use ES256 when smaller key sizes and faster signature verification matter.

---

## FastAPI integration

### Token validation dependency

Consumer services validate tokens locally and check revocation via HTTP (not direct Redis access).
See `examples/fastapi_service/core/deps.py` in [fa-auth-m8](https://github.com/mano8/fa-auth-m8)
for the full reference implementation. The key pieces:

```python
from typing import Annotated
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.user import UserModel
from auth_sdk_m8.security import build_access_validator

oauth2 = OAuth2PasswordBearer(tokenUrl="/user/login/access-token")
TokenDep = Annotated[str, Depends(oauth2)]

_validator = build_access_validator(settings)  # module-level singleton

async def get_current_user(token: TokenDep) -> UserModel:
    try:
        payload = _validator.validate_access_token(token)
    except InvalidToken as exc:
        raise HTTPException(status_code=403, detail="Could not validate credentials.") from exc
    # Revocation: call auth service HTTP endpoint (not Redis directly)
    # See RemoteRevocationClient in fa-auth-m8 examples/fastapi_service/core/revocation.py
    return UserModel(**{**payload.model_dump(exclude={"sub", "jti", "exp", "type"}), "id": payload.sub})
```

> **Redis isolation:** consumer services must not connect to auth Redis.
> Use `POST /private/v1/jti-status` on the auth service instead (see [fa-auth-m8](https://github.com/mano8/fa-auth-m8)).

### Startup config validation

Call `check_config_health` inside the FastAPI lifespan to surface misconfigurations before the
first request:

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
from auth_sdk_m8.core.config import check_config_health
import logging

_logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    check_config_health(settings, _logger)  # raises ConfigurationError on fatal issues
    yield

app = FastAPI(lifespan=lifespan)
```

Checks performed:

| Condition | Severity |
| --- | --- |
| RS256/ES256 without `ACCESS_PUBLIC_KEY_FILE` or `JWKS_URI` | **fatal** |
| `JWKS_URI` set but algorithm is `HS256` | warning |
| `AUTH_SERVICE_ROLE=consumer` with `ACCESS_PRIVATE_KEY_FILE` | **fatal** |
| `AUTH_SERVICE_ROLE=issuer` with asymmetric algorithm but no private key | **fatal** |
| `AUTH_SERVICE_ROLE=issuer` with `JWKS_URI` set | warning (fatal under `STRICT_PRODUCTION_MODE`) |
| `AUTH_SERVICE_ROLE=issuer` + `TOKEN_MODE=stateful/hybrid` without Redis credentials | **fatal** (via `_enforce_redis_for_issuers`) |
| `JWKS_CACHE_TTL_SECONDS` below 30 s | warning |
| `ENVIRONMENT=production` with `localhost`/`127.0.0.1` in `ALLOWED_ORIGINS` | **fatal** |
| `ENVIRONMENT=production` with `SET_DOCS=true` or `SET_OPEN_API=true` (and **not** `SERVE_DOCS_IN_PRODUCTION`) | warning (fatal under `STRICT_PRODUCTION_MODE`) |
| `ENVIRONMENT=production` with `SERVE_DOCS_IN_PRODUCTION=true` (docs intentionally published) | warning (never fatal — explicit opt-in) |
| `AUTH_SERVICE_ROLE=consumer` + `TOKEN_MODE=stateless` + `DB_HOST` set | warning |
| `STRICT_PRODUCTION_MODE=true` with wildcard `*` in `ALLOWED_ORIGINS` | **fatal** |
| `STRICT_PRODUCTION_MODE=true` with `SESSION_COOKIE_SECURE=false` outside `local` | **fatal** |

---

## Docs / OpenAPI gating (secure-by-default)

`SET_OPEN_API`, `SET_DOCS`, and `SET_REDOC` keep their `True` defaults for developer
experience, but the interactive API docs (OpenAPI schema, Swagger UI, ReDoc) are **gated off in
production by default**. Rather than reading the raw `SET_*` flags directly, mount your docs
endpoints from the three computed properties, which are the single source of truth every consumer
inherits:

| Property | Value |
| --- | --- |
| `effective_set_open_api` | `SET_OPEN_API` **and not** gated |
| `effective_set_docs` | `SET_DOCS` **and not** gated |
| `effective_set_redoc` | `SET_REDOC` **and not** gated |

where **gated** = production **and not** `SERVE_DOCS_IN_PRODUCTION`.

Production is `ENVIRONMENT == "production"` **or** `STRICT_PRODUCTION_MODE == true`. In production all
three effective flags resolve to `False` regardless of the raw `SET_*` values — **unless** you set
`SERVE_DOCS_IN_PRODUCTION=true` to explicitly publish docs (e.g. a public / open-source API).
Secure-by-default, but the operator can opt in.

```python
from fastapi import FastAPI
from auth_sdk_m8.core.config import CommonSettings

settings = CommonSettings()  # your concrete settings

app = FastAPI(
    openapi_url="/openapi.json" if settings.effective_set_open_api else None,
    docs_url="/docs" if settings.effective_set_docs else None,
    redoc_url="/redoc" if settings.effective_set_redoc else None,
)
```

**Opting back on:** docs are available by default in every non-production environment (`local`,
`development`, `staging`). To serve them **in production**, set `SERVE_DOCS_IN_PRODUCTION=true` (the
raw `SET_*` flags still apply per-endpoint).

> ⚠️ **Risk — never silent.** Publishing docs in production exposes a live interactive
> Swagger/ReDoc console wired to your production server. `check_config_health` **always logs a
> warning** while `SERVE_DOCS_IN_PRODUCTION=true` so the choice is never accidental (it is *not*
> escalated to fatal, even under strict mode — it's your explicit decision).

When the opt-in is **not** set, leaving raw `SET_DOCS`/`SET_OPEN_API` `true` in production also
triggers a `check_config_health` warning (fatal under strict mode), nudging you to disable them.

---

## Service role (`AUTH_SERVICE_ROLE`)

Set `AUTH_SERVICE_ROLE` to declare whether a service issues tokens or only validates them.
`check_config_health` uses this to enforce role-appropriate key configuration.

```ini
# auth_user_service — signs tokens and serves JWKS
AUTH_SERVICE_ROLE=issuer

# any consumer microservice — only validates
AUTH_SERVICE_ROLE=consumer
```

| Role | Allowed | Rejected |
| --- | --- | --- |
| `issuer` | `ACCESS_PRIVATE_KEY_FILE` + `ACCESS_PUBLIC_KEY_FILE` | missing private key with asymmetric algorithm |
| `consumer` | `JWKS_URI` or `ACCESS_PUBLIC_KEY_FILE` | `ACCESS_PRIVATE_KEY_FILE` (private key on a consumer is always fatal) |

---

## Consumer settings mixin (`ConsumerAuthMixin`)

Consumer microservices that use HTTP introspection should mix `ConsumerAuthMixin` into their settings class. It adds `INTROSPECTION_URL` and `PRIVATE_API_SECRET` and enforces that both are set when `TOKEN_MODE` is `stateful` or `hybrid`.

```python
from auth_sdk_m8.core import ConsumerAuthMixin
from auth_sdk_m8.core.config import CommonSettings

class MyServiceSettings(ConsumerAuthMixin, CommonSettings):
    ...  # your service-specific fields
```

Required fields added by the mixin:

| Field | Type | Description |
| --- | --- | --- |
| `INTROSPECTION_URL` | `AnyHttpUrl \| None` | Full URL of the auth service JTI-status endpoint, e.g. `https://auth.example.com/user/private/v1/jti-status` |
| `PRIVATE_API_SECRET` | `SecretStr \| None` | Shared secret presented in `X-Internal-Token` for introspection requests |

Both fields default to `None` (stateless mode). The `_require_introspection_for_stateful_consumer` validator raises `ValueError` when `TOKEN_MODE` is `stateful` or `hybrid` and either field is unset.

> `fastapi-m8`'s `ConsumerServiceSettings` already inherits `ConsumerAuthMixin` — you only need to mix it in manually if you build a consumer without fastapi-m8.

---

## Asymmetric key-strength enforcement

`CommonSettings` validates loaded key material at startup:

- **RS256**: minimum **2048-bit** RSA key — smaller keys raise `ValueError` and abort startup.
- **ES256**: requires a **P-256 (secp256r1)** EC key — other curves (P-384, secp256k1, …) are rejected.

This runs for both private keys (issuer) and public keys (consumer with `ACCESS_PUBLIC_KEY_FILE`).
Consumer services using `JWKS_URI` skip this check — key strength is validated by the issuer.

---

## Strict production mode

Set `STRICT_PRODUCTION_MODE=true` to escalate security warnings to fatal errors, aborting
startup instead of merely logging. Recommended for staging/production CI gates.

```ini
STRICT_PRODUCTION_MODE=true
SESSION_COOKIE_SECURE=true
SET_DOCS=false
SET_OPEN_API=false
```

What strict mode adds on top of the base `check_config_health` checks:

- `SET_DOCS=true` or `SET_OPEN_API=true` in production → **fatal** (base: warning)
- `AUTH_SERVICE_ROLE=issuer` with `JWKS_URI` set → **fatal** (base: warning)
- Wildcard `*` in `ALLOWED_ORIGINS` → **fatal**
- `SESSION_COOKIE_SECURE=false` outside `ENVIRONMENT=local` → **fatal**
- `TOKEN_ISSUER` or `TOKEN_AUDIENCE` not set in production → **fatal** (base: warning)

---

## Token modes

Set `TOKEN_MODE` to control session strategy. Both auth service and consumers must agree.

| `TOKEN_MODE` | Access tokens | Refresh tokens | Redis required (issuer) | Redis required (consumer) |
| --- | --- | --- | --- | --- |
| `stateless` | pure JWT, no revocation | pure JWT | no | no |
| `hybrid` | pure JWT | JTI tracked in Redis | yes | no |
| `stateful` | JTI blacklisted in Redis | JTI tracked in Redis | yes | no — use HTTP introspection |

`requires_redis` returns `True` only for `AUTH_SERVICE_ROLE=issuer` with `TOKEN_MODE` ≠ `stateless`.
Consumer services never hold Redis credentials — they call `POST /private/v1/jti-status` on the
auth service instead (see [fa-auth-m8](https://github.com/mano8/fa-auth-m8) for the reference
`RemoteRevocationClient`).

---

## Refresh key rotation

`REFRESH_SECRET_KEY_OLD` provides a zero-downtime rotation window for the refresh token signing key. When set, any refresh token that fails validation against the current `REFRESH_SECRET_KEY` is automatically retried against the old key. A `WARNING` is logged each time the old key is used so you can track when all legacy tokens have expired.

**Rotation procedure:**

1. Generate a new key and set it as `REFRESH_SECRET_KEY`.
2. Move the previous key to `REFRESH_SECRET_KEY_OLD`.
3. Deploy — old-key tokens validate via fallback; new tokens are signed with the new key.
4. Once all refresh tokens issued before the rotation have expired (after `REFRESH_TOKEN_EXPIRE_MINUTES`), remove `REFRESH_SECRET_KEY_OLD` and redeploy.

> **Note:** Expired tokens are never retried against the old key — expiry is independent of the signing key.

```ini
REFRESH_SECRET_KEY=new-strong-secret
REFRESH_SECRET_KEY_OLD=previous-strong-secret
```

---

## Redis TLS

Set `REDIS_SSL=true` to enable TLS on the `ConnectionPool` when Redis is reached over a network boundary in staging/production. Defaults to `false` for plain-TCP local/dev stacks.

| Setting | Required | Description |
| --- | --- | --- |
| `REDIS_SSL` | no | `true` to enable TLS (default `false`) |
| `REDIS_SSL_CA` | when `REDIS_SSL=true` | Path to CA certificate — required to verify the Redis server cert |
| `REDIS_SSL_CERT` | no | Path to client certificate for mTLS — must be set together with `REDIS_SSL_KEY` |
| `REDIS_SSL_KEY` | no | Path to client private key for mTLS — must be set together with `REDIS_SSL_CERT` |

`REDIS_SSL_CERT` and `REDIS_SSL_KEY` follow an XOR rule: both must be set or both unset. All path fields are validated at startup — a missing file aborts startup immediately.

```ini
# TLS only (server cert verification)
REDIS_SSL=true
REDIS_SSL_CA=/opt/certs/ca.crt

# mTLS (mutual TLS — client cert + key)
REDIS_SSL=true
REDIS_SSL_CA=/opt/certs/ca.crt
REDIS_SSL_CERT=/opt/certs/client.crt
REDIS_SSL_KEY=/opt/certs/client.key
```

---

## Chrome extension / native-app OAuth support

`CommonSettings` provides three settings for deploying `fa-auth-m8` as a backend
for Chrome extensions or native-app OAuth clients.

| Setting | Default | Purpose |
| --- | --- | --- |
| `OAUTH_ALLOWED_REDIRECT_SCHEMES` | `["chrome-extension://"]` | URI schemes accepted as `redirect_target` at the login-URL endpoint. `http://` and `https://` are always hard-rejected regardless of this list. |
| `OAUTH_ALLOWED_REDIRECT_PREFIXES` | `[]` | Optional full-URI allowlist for operator-controlled extension binding. Empty = open public-client model (any extension with the correct scheme). |
| `CORS_ALLOWED_ORIGIN_SCHEMES` | `[]` | URI scheme prefixes allowed as `Origin` in CORS preflight requests. Required for Chrome extension `fetch()` calls. |

Both settings accept comma-separated strings from env vars:

```ini
# Accept any chrome-extension:// redirect (open public-client model)
OAUTH_ALLOWED_REDIRECT_SCHEMES=chrome-extension://

# Optional: restrict to specific extension IDs
OAUTH_ALLOWED_REDIRECT_PREFIXES=chrome-extension://abcdefghijklmnopqrstuvwxyzabcdef/

# Enable CORS for extension fetch() calls
CORS_ALLOWED_ORIGIN_SCHEMES=chrome-extension://
```

`CORS_ALLOWED_ORIGIN_SCHEMES` is consumed by `fa-auth-m8`'s `CORSMiddleware`
setup (`_build_cors_origin_regex`). Chrome extension IDs are constrained to
exactly 32 lowercase letters; the middleware rejects any origin that does not
match. Only `chrome-extension://` is a supported scheme value — other
schemes require custom CORS validation.

`EXTENSION_ID` (present in versions ≤ 0.6.12) has been removed. `fa-auth-m8`
is a generic auth provider; it must not require per-client backend configuration.

---

## Auth degradation policy

When Redis is unavailable, each security control can independently `fail_open` (allow the request through) or `fail_closed` (return HTTP 503). Set these in `CommonSettings` or your `.env`:

| Setting | Default | Controls |
| --- | --- | --- |
| `AUTH_STRICT_MODE` | `false` | When `true`, overrides all per-control modes to `fail_closed` |
| `REFRESH_VALIDATION_FAILURE_MODE` | `fail_closed` | Refresh token allowlist check |
| `SESSION_WRITE_FAILURE_MODE` | `fail_closed` | Session write on login / logout revocation |
| `RATE_LIMIT_FAILURE_MODE` | `fail_open` | Refresh rate limiter |
| `ACCESS_REVOCATION_FAILURE_MODE` | `fail_closed` | Access token JTI blacklist check |

> **Security note:** `ACCESS_REVOCATION_FAILURE_MODE` defaults to `fail_closed` — any outage (auth service, Redis, network) that prevents verifying token revocation returns HTTP 503 rather than accepting a potentially-revoked token. Availability-first stacks can set `ACCESS_REVOCATION_FAILURE_MODE=fail_open` to preserve service availability during outages. High-security stacks can set `AUTH_STRICT_MODE=true` to force all controls closed regardless of individual settings.

```ini
# Harden everything — any Redis outage blocks the request
AUTH_STRICT_MODE=true

# Availability-first: allow requests when revocation check unavailable
ACCESS_REVOCATION_FAILURE_MODE=fail_open

# Or tune per-control (AUTH_STRICT_MODE must be false/unset)
RATE_LIMIT_FAILURE_MODE=fail_closed
```

Resolve the effective mode programmatically:

```python
mode = settings.effective_failure_mode("rate_limit")  # "fail_open" | "fail_closed"
```

`effective_failure_mode` accepts: `"refresh_validation"`, `"session_write"`, `"rate_limit"`, `"access_revocation"`.

---

## Rate limiting

`LoginRateLimiter` and `RefreshRateLimiter` limits are configurable via `CommonSettings`. Defaults represent the recommended security posture; a startup warning is logged when the effective rate exceeds the per-control threshold.

| Setting | Default | Bounds | Threshold warning |
| --- | --- | --- | --- |
| `LOGIN_RATE_LIMIT_REQUESTS` | `5` | 1–1000 | > 5 req/min combined |
| `LOGIN_RATE_LIMIT_WINDOW_MINUTES` | `15` | 1–1440 | — |
| `REFRESH_RATE_LIMIT_REQUESTS` | `10` | 1–1000 | > 20 req/min combined |
| `REFRESH_RATE_LIMIT_WINDOW_MINUTES` | `5` | 1–1440 | — |

```ini
# Tighten for high-value deployments
LOGIN_RATE_LIMIT_REQUESTS=3
LOGIN_RATE_LIMIT_WINDOW_MINUTES=30
REFRESH_RATE_LIMIT_REQUESTS=5
REFRESH_RATE_LIMIT_WINDOW_MINUTES=10
```

The refresh vars are unused in `TOKEN_MODE=stateless` (no refresh tokens are issued). `_check_rate_limit_config()` in `config_health.py` skips the refresh check automatically in that mode.

---

## Issuer / audience enforcement

Set these in both the auth service and consumers to prevent token reuse across services:

```ini
TOKEN_ISSUER=https://auth.example.com
TOKEN_AUDIENCE=https://api.example.com
```

`build_access_validator` automatically enforces `iss` and `aud` claims when these are set.

---

## Refresh token rotation

`RefreshTokenPolicy` enforces one-time use and atomic JTI rotation. A reused token is rejected
immediately — treat that as a compromise signal.

```python
from auth_sdk_m8.security import RefreshTokenPolicy
import uuid

policy = RefreshTokenPolicy(secrets=refresh_secrets, store=my_refresh_store)

# On each /refresh request:
user_id, old_jti = await policy.validate_and_rotate(
    token=refresh_token,
    new_jti=str(uuid.uuid4()),
    ttl_seconds=86_400,
)
# Issue a new token pair for user_id. old_jti is now revoked.

# On logout:
await policy.revoke(jti)
```

Implement `RefreshTokenStore` against any backend:

```python
class RedisRefreshStore:
    def __init__(self, redis): self._r = redis

    async def is_valid(self, jti: str) -> bool:
        return bool(await self._r.exists(f"rt:{jti}"))

    async def rotate(self, old_jti: str, new_jti: str, ttl_seconds: int) -> None:
        pipe = self._r.pipeline()
        pipe.delete(f"rt:{old_jti}")
        pipe.setex(f"rt:{new_jti}", ttl_seconds, "1")
        await pipe.execute()

    async def revoke(self, jti: str) -> None:
        await self._r.delete(f"rt:{jti}")
```

---

## Observability hooks

Attach logging, metrics, or tracing to token validation events via `ValidationHooks`:

```python
import logging
from auth_sdk_m8.security import ValidationHooks, build_access_validator

class LogHooks:
    def on_success(self, *, jti: str, sub: str, token_type: str) -> None:
        logging.info("token_ok type=%s sub=%s", token_type, sub)

    def on_failure(self, *, reason: str, token_type: str) -> None:
        logging.warning("token_fail type=%s reason=%s", token_type, reason)

validator = build_access_validator(settings, hooks=LogHooks())
```

Failure reasons: `"expired"`, `"invalid"`, `"wrong_type"`, `"invalid_payload"`, `"revoked"`, `"reused"`.

---

## Prometheus metrics

Requires `pip install "auth-sdk-m8[observability]"`.

```python
# main.py
from auth_sdk_m8.observability import metrics as _metrics
from auth_sdk_m8.observability.middleware import MetricsMiddleware
from auth_sdk_m8.observability.settings import ObservabilitySettingsMixin
from fastapi import FastAPI, Response

class Settings(ObservabilitySettingsMixin, CommonSettings):
    ...

_metrics.setup(
    enabled=settings.METRICS_ENABLED,
    groups_str=settings.METRICS_GROUPS,
    api_prefix=settings.API_PREFIX,
)

app = FastAPI(...)
if settings.METRICS_ENABLED:
    app.add_middleware(MetricsMiddleware)

    @app.get(f"{settings.API_PREFIX}/metrics", include_in_schema=False)
    def metrics_endpoint() -> Response:
        content, content_type = _metrics.render()
        return Response(content=content, media_type=content_type)
```

```ini
METRICS_ENABLED=true
METRICS_GROUPS=all   # or: traffic,performance,reliability,health,auth
```

| Group | Metrics |
| --- | --- |
| `traffic` | `http_requests_total` (method, endpoint, status_code) |
| `performance` | `http_request_duration_seconds` histogram |
| `reliability` | `http_errors_total` (4xx/5xx) |
| `health` | `http_status_total` by exact status code |
| `auth` | `token_login_total`, `token_refresh_total` (result: success\|failure\|rate_limited), `token_logout_total`, `token_validation_failure_total`, `oauth_attempt_total`, `auth_code_exchange_total` (result: success\|expired_or_invalid\|pkce_failed\|redis_unavailable), `auth_revocation_failure_total` (operation: access_blacklist\|refresh_allowlist\|db_session), `auth_degraded_decision_total` (control, mode, reason), `auth_redis_circuit_breaker_open` (gauge: 0=closed 1=open), `auth_degradation_mode_active` (gauge per control+mode), `auth_session_integrity_denial_total` (trigger: reuse_detected) |

---

## Redis event bus

```python
import asyncio
from auth_sdk_m8.redis_events.event_bus import EventBus
from auth_sdk_m8.schemas.user_events import UserDeletedEvent

bus = EventBus(redis_url="redis://localhost:6379")

async def on_user_deleted(event: UserDeletedEvent) -> None:
    print(f"User {event.user_id} deleted — cleaning up local data.")

async def main():
    await bus.subscribe("user.deleted", UserDeletedEvent, on_user_deleted)
    await asyncio.sleep(3600)

asyncio.run(main())
```

---

## Package layout

```text
auth_sdk_m8/
├── schemas/
│   ├── auth.py          # TokenUserData, TokenAccessData, TokenSecret, ASYMMETRIC_ALGORITHMS
│   ├── base.py          # AuthProviderType, RoleType, Period, response models
│   ├── shared.py        # ValidationConstants (regex patterns)
│   ├── user.py          # UserModel, SessionModel
│   └── user_events.py   # UserDeletedEvent
├── core/
│   ├── config.py        # CommonSettings, check_config_health, SecretProvider
│   ├── exceptions.py    # InvalidToken, ConfigurationError
│   └── security.py      # ComSecurityHelper (legacy: PKCE, token hashing)
├── security/
│   ├── factory.py            # build_access_validator() — settings-driven factory
│   ├── blacklist.py          # AccessTokenBlacklist — Redis JTI revocation check
│   ├── jwks_resolver.py      # JwksKeyResolver — JWKS endpoint with TTL cache
│   ├── token_validator.py    # TokenValidator — stateless JWT validation
│   ├── token_policy.py       # TokenPolicy — stateful validation with revocation store
│   ├── refresh_token_policy.py  # RefreshTokenPolicy — one-time-use rotation
│   ├── refresh_token_store.py   # RefreshTokenStore protocol
│   ├── session_store.py      # SessionStore protocol
│   ├── key_resolver.py       # KeyResolver protocol
│   ├── hooks.py              # ValidationHooks protocol
│   └── validation.py         # TokenValidationConfig
├── observability/
│   ├── metrics.py        # setup(), get(), render()
│   ├── middleware.py     # MetricsMiddleware
│   └── settings.py       # ObservabilitySettingsMixin
├── redis_events/
│   ├── event_bus.py      # EventBus (typed pub/sub)
│   ├── publisher.py      # EventPublisher
│   └── subscriber.py     # EventSubscriber
├── controllers/
│   └── base.py           # BaseController: exception → JSONResponse
├── models/
│   └── shared.py         # TimestampMixin, Message, Token, TokenPayload
└── utils/
    ├── errors_parser.py  # parse_integrity_error (MySQL + PostgreSQL), parse_pydantic_errors
    └── paths.py          # find_dotenv
```

---

## Architecture note

This SDK is intentionally thin — no business logic, only schemas, validation helpers, and base
classes. JWTs are validated locally (no network call per request). `auth_user_service` is the
sole token **issuer**; this SDK provides the tools to **read** and **rotate** them.

For multi-team or multi-service deployments use **RS256** with JWKS: consumers only need the
JWKS URI, never the signing key.
