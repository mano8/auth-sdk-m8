# auth-sdk-m8

Shared authentication schemas, JWT validation, and FastAPI base components for **m8 microservices**.

Extracted from `auth_user_service` and installed by any service that integrates with it via Docker Compose.
Provides Pydantic schemas, JWT validation, `CommonSettings`, Redis event bus, and optional Prometheus metrics.

[![PyPI version](https://img.shields.io/pypi/v/auth-sdk-m8)](https://pypi.org/project/auth-sdk-m8/)
[![Python](https://img.shields.io/pypi/pyversions/auth-sdk-m8)](https://pypi.org/project/auth-sdk-m8/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/auth-sdk-m8?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/auth-sdk-m8)
[![codecov](https://codecov.io/gh/mano8/auth-sdk-m8/graph/badge.svg?token=TF6OGIHOGF)](https://codecov.io/gh/mano8/auth-sdk-m8)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/8b8e9726b0f8441ea480902ea8910812)](https://app.codacy.com/gh/mano8/auth-sdk-m8/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

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

---

## FastAPI integration

### Token validation dependency

```python
from typing import Annotated, Optional
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from redis import Redis
from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.user import UserModel
from auth_sdk_m8.security import AccessTokenBlacklist, build_access_validator

oauth2 = OAuth2PasswordBearer(tokenUrl="/user/login/access-token")
TokenDep = Annotated[str, Depends(oauth2)]

_validator = build_access_validator(settings)  # module-level singleton

def get_redis() -> Optional[Redis]:
    try:
        r = Redis(host=settings.REDIS_HOST, port=settings.REDIS_PORT,
                  decode_responses=True, socket_connect_timeout=1)
        r.ping()
        return r
    except Exception:
        return None

RedisDep = Annotated[Optional[Redis], Depends(get_redis)]

def get_current_user(token: TokenDep, redis: RedisDep) -> UserModel:
    try:
        payload = _validator.validate_access_token(token)
    except InvalidToken as exc:
        raise HTTPException(status_code=403, detail="Could not validate credentials.") from exc

    if settings.TOKEN_MODE != "stateless" and redis is not None:
        if AccessTokenBlacklist(redis).is_revoked(payload.jti):
            raise HTTPException(status_code=403, detail="Token has been revoked.")

    return UserModel(**{**payload.model_dump(exclude={"sub", "jti", "exp", "type"}), "id": payload.sub})
```

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
| `TOKEN_MODE=stateful/hybrid` without Redis credentials | **fatal** |
| `JWKS_CACHE_TTL_SECONDS` below 30 s | warning |
| `ENVIRONMENT=production` with `localhost`/`127.0.0.1` in `ALLOWED_ORIGINS` | **fatal** |
| `ENVIRONMENT=production` with `SET_DOCS=true` or `SET_OPEN_API=true` | warning (fatal under `STRICT_PRODUCTION_MODE`) |
| `AUTH_SERVICE_ROLE=consumer` + `TOKEN_MODE=stateless` + `DB_HOST` set | warning |
| `STRICT_PRODUCTION_MODE=true` with wildcard `*` in `ALLOWED_ORIGINS` | **fatal** |
| `STRICT_PRODUCTION_MODE=true` with `SESSION_COOKIE_SECURE=false` outside `local` | **fatal** |

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

---

## Token modes

Set `TOKEN_MODE` to control session strategy. Both auth service and consumers must agree.

| `TOKEN_MODE` | Access tokens | Refresh tokens | Redis required |
| --- | --- | --- | --- |
| `stateless` | pure JWT, no revocation | pure JWT | no |
| `hybrid` | pure JWT | JTI tracked in Redis | yes |
| `stateful` | JTI blacklisted in Redis | JTI tracked in Redis | yes |

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
| `auth` | login attempts, token refresh, logout, validation failures, OAuth attempts |

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

---

## Publishing a new version

1. Bump `version` in `pyproject.toml` and `auth_sdk_m8/__init__.py`
2. Add an entry to `CHANGELOG.md`
3. Run `pytest` (must reach ≥ 90 % coverage) and `ruff check .`
4. Commit, tag, and push: `git tag v0.x.y && git push origin v0.x.y`
5. GitHub Actions publishes to PyPI automatically
