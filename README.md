# auth-sdk-m8

Shared authentication schemas, JWT utilities, and FastAPI base components for **m8 microservices**.

This package is extracted from `auth_user_service` and is intended to be installed by any service
that integrates with it via Docker Compose. It provides the Pydantic schemas matching the auth
service's API, JWT validation helpers, and optional FastAPI/SQLModel base classes.

[![PyPI version](https://img.shields.io/pypi/v/auth-sdk-m8)](https://pypi.org/project/auth-sdk-m8/)
[![Python](https://img.shields.io/pypi/pyversions/auth-sdk-m8)](https://pypi.org/project/auth-sdk-m8/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/auth-sdk-m8?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/auth-sdk-m8)
---

## Installation

### From PyPI (recommended)

```bash
pip install auth-sdk-m8 --upgrade
```

### Directly from GitHub

```bash
pip install "auth-sdk-m8 @ git+https://github.com/mano8/auth-sdk-m8.git@v0.2.0"
```

### For development (editable install)

```bash
git clone https://github.com/mano8/auth-sdk-m8.git
cd auth-sdk-m8
pip install -e ".[all,dev]"
```

---

## Optional dependency groups

Install only what your service needs:

| Extra | Installs | Use when |
| --- | --- | --- |
| *(none)* | `pydantic`, `email-validator` | schemas only |
| `[security]` | `PyJWT` | local JWT validation |
| `[fastapi]` | `fastapi` | cookie helpers, `BaseController` |
| `[redis]` | `redis` | Redis event bus |
| `[config]` | `pydantic-settings` | `CommonSettings` base class |
| `[db]` | `sqlmodel`, `sqlalchemy` | `TimestampMixin`, DB error parsing |
| `[mysql]` | `pymysql` | MySQL database driver |
| `[postgres]` | `psycopg2-binary` | PostgreSQL database driver |
| `[observability]` | `prometheus-client`, `fastapi` | Prometheus metrics middleware |
| `[all]` | everything above | full feature set |

Examples:

```bash
# A FastAPI service using MySQL
pip install "auth-sdk-m8[security,fastapi,db,mysql]"

# A FastAPI service using PostgreSQL
pip install "auth-sdk-m8[security,fastapi,db,postgres]"

# A service that only validates tokens locally
pip install "auth-sdk-m8[security]"

# A service that only listens to Redis events
pip install "auth-sdk-m8[redis]"

# A service with Prometheus metrics support
pip install "auth-sdk-m8[observability]"
```

---

## Quick start

### Validate a JWT from auth_user_service

```python
from pydantic import SecretStr
from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.auth import TokenSecret
from auth_sdk_m8.security import TokenValidationConfig, TokenValidator

validator = TokenValidator(
    secrets=TokenSecret(
        secret_key=SecretStr(ACCESS_SECRET_KEY),
        algorithm="HS256",
    ),
    config=TokenValidationConfig(),
)

try:
    payload = validator.validate_access_token(bearer_token)
    print(payload.email, payload.role)
except InvalidToken:
    # token expired or invalid signature
    ...
```

### FastAPI dependency for token validation

```python
from typing import Annotated
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from pydantic import SecretStr
from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.auth import TokenSecret
from auth_sdk_m8.schemas.user import UserModel
from auth_sdk_m8.security import TokenValidationConfig, TokenValidator

oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/login/access-token")
TokenDep = Annotated[str, Depends(oauth2)]

# Create once at module level — avoid re-instantiating on every request.
_validator = TokenValidator(
    secrets=TokenSecret(
        secret_key=SecretStr(settings.ACCESS_SECRET_KEY),
        algorithm=settings.ACCESS_TOKEN_ALGORITHM,
    ),
    config=TokenValidationConfig(),
)

def get_current_user(token: TokenDep) -> UserModel:
    try:
        payload = _validator.validate_access_token(token)
    except InvalidToken as exc:
        raise HTTPException(status_code=403, detail="Could not validate credentials.") from exc
    payload_dict = payload.model_dump(exclude={"sub", "jti", "exp", "type"})
    payload_dict["id"] = payload.sub
    return UserModel(**payload_dict)
```

### Extend CommonSettings for your service

```python
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
    # add service-specific fields here
    MY_SERVICE_SECRET: str

settings = Settings()
```

Set `SELECTED_DB` in your `.env` to choose the database backend (defaults to `Mysql`):

```ini
# .env
SELECTED_DB=Postgres   # or Mysql (default)
DB_HOST=localhost
DB_PORT=5432
DB_DATABASE=mydb
DB_USER=myuser
DB_PASSWORD=MyPassw0rd!
```

`settings.SQLALCHEMY_DATABASE_URI` returns the appropriate SQLAlchemy connection string for the
selected backend (`mysql+pymysql://…` or `postgresql+psycopg2://…`).

### Listen to Redis events from auth_user_service

```python
import asyncio
from auth_sdk_m8.redis_events.event_bus import EventBus
from auth_sdk_m8.schemas.user_events import UserDeletedEvent

bus = EventBus(redis_url="redis://localhost:6379")

async def on_user_deleted(event: UserDeletedEvent) -> None:
    print(f"User {event.user_id} was deleted — cleaning up local data.")

async def main():
    await bus.subscribe("user.deleted", UserDeletedEvent, on_user_deleted)
    await asyncio.sleep(3600)  # keep running

asyncio.run(main())
```

---

## Package layout

```text
auth_sdk_m8/
├── schemas/
│   ├── auth.py          # JWT payload schemas (TokenUserData, TokenAccessData, TokenSecret, …)
│   ├── base.py          # Enums (AuthProviderType, RoleType, Period) + response models
│   ├── shared.py        # ValidationConstants (regex patterns)
│   ├── user.py          # UserModel, SessionModel
│   ├── redis_events.py  # EventBase
│   └── user_events.py   # UserDeletedEvent
├── core/
│   ├── config.py        # CommonSettings (pydantic-settings base class)
│   ├── exceptions.py    # InvalidToken
│   └── security.py      # ComSecurityHelper (legacy helpers: PKCE, token hashing)
├── security/
│   ├── token_validator.py       # TokenValidator — stateless JWT access-token validation
│   ├── token_policy.py          # TokenPolicy — stateful validation with revocation store
│   ├── refresh_token_policy.py  # RefreshTokenPolicy — one-time-use refresh token rotation
│   ├── refresh_token_store.py   # RefreshTokenStore protocol (implement against Redis, DB, …)
│   ├── session_store.py         # SessionStore protocol (revocation checks)
│   ├── key_resolver.py          # KeyResolver protocol (dynamic kid-based key lookup)
│   ├── hooks.py                 # ValidationHooks protocol (observability callbacks)
│   └── validation.py            # TokenValidationConfig (algorithm whitelist, claim rules)
├── redis_events/
│   ├── event_bus.py     # EventBus (typed pub/sub)
│   ├── publisher.py     # EventPublisher
│   └── subscriber.py   # EventSubscriber
├── controllers/
│   └── base.py          # BaseController: unified exception → JSONResponse
├── models/
│   └── shared.py        # TimestampMixin, Message, Token, TokenPayload (SQLModel)
└── utils/
    ├── errors_parser.py # parse_integrity_error (MySQL + PostgreSQL), parse_pydantic_errors
    └── paths.py         # find_dotenv
```

---

## Publishing a new version

1. Bump `version` in `pyproject.toml`
2. Add an entry to `CHANGELOG.md`
3. Commit and push
4. Create a git tag: `git tag v0.2.0 && git push origin v0.2.0`
5. GitHub Actions builds and publishes automatically to PyPI

---

## Architecture note

This SDK is intentionally thin. It contains **no business logic** — only schemas,
validation helpers, and infrastructure base classes. Each consuming service validates
JWTs locally (no network call per request). The `auth_user_service` remains the sole
authority for **issuing** tokens; this SDK provides the tools to **read** and **rotate** them.

For multi-team deployments consider **RS256** or **ES256** asymmetric signing — consuming
services only need the public key, never the signing secret.

---

## Validation models

### Stateless (default)

Pure JWT validation with no I/O dependency — recommended for most services.

```python
from pydantic import SecretStr
from auth_sdk_m8.schemas.auth import TokenSecret
from auth_sdk_m8.security import TokenValidationConfig, TokenValidator

validator = TokenValidator(
    secrets=TokenSecret(
        secret_key=SecretStr(ACCESS_SECRET_KEY),
        algorithm="HS256",
    ),
    config=TokenValidationConfig(),
)

payload = validator.validate_access_token(token)
```

### Stateful (optional)

Adds revocation checks via `SessionStore` — use for admin APIs or high-risk operations.

```python
from auth_sdk_m8.security import TokenPolicy

policy = TokenPolicy(validator, store=my_session_store)
payload = await policy.validate(token)  # raises InvalidToken if JTI is revoked
```

### Refresh token rotation

`RefreshTokenPolicy` enforces one-time use and atomic JTI rotation. A reused refresh
token is rejected immediately, which acts as a compromise signal.

```python
import uuid
from auth_sdk_m8.security import RefreshTokenPolicy

policy = RefreshTokenPolicy(
    secrets=refresh_secrets,
    store=my_refresh_store,  # implements RefreshTokenStore protocol
)

# On each refresh request:
user_id, old_jti = await policy.validate_and_rotate(
    token=refresh_token,
    new_jti=str(uuid.uuid4()),
    ttl_seconds=86_400,
)
# old_jti is now revoked; issue a new token pair for user_id

# On logout:
await policy.revoke(jti)
```

Implement `RefreshTokenStore` against Redis or any backend:

```python
class RedisRefreshStore:
    def __init__(self, redis) -> None:
        self._r = redis

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

### Prometheus metrics

Instrument any FastAPI / Starlette service with optional Prometheus metrics.
Requires `pip install "auth-sdk-m8[observability]"`.

```python
# main.py
from auth_sdk_m8.observability import metrics as _metrics
from auth_sdk_m8.observability.middleware import MetricsMiddleware
from fastapi import FastAPI, Response

# Call once at startup — no-op when enabled=False.
_metrics.setup(
    enabled=settings.METRICS_ENABLED,
    groups_str=settings.METRICS_GROUPS,   # e.g. "all" or "traffic,performance"
    api_prefix=settings.API_PREFIX,        # e.g. "/user"  → metric prefix "user_"
)

app = FastAPI(...)

if settings.METRICS_ENABLED:
    app.add_middleware(MetricsMiddleware)

    @app.get(f"{settings.API_PREFIX}/metrics", include_in_schema=False, tags=["observability"])
    def metrics_endpoint() -> Response:
        content, content_type = _metrics.render()
        return Response(content=content, media_type=content_type)
```

Add `ObservabilitySettingsMixin` to your settings class:

```python
from auth_sdk_m8.observability.settings import ObservabilitySettingsMixin
from auth_sdk_m8.core.config import CommonSettings

class Settings(ObservabilitySettingsMixin, CommonSettings):
    ...
```

Then in your `.env`:

```ini
# Master switch — when false the /metrics endpoint is never registered.
METRICS_ENABLED=true

# Which groups to collect.  Comma-separated or "all".
# Groups: traffic | performance | reliability | health | auth
METRICS_GROUPS=all
```

#### Metric groups

| Group | Metric | Labels |
| --- | --- | --- |
| `traffic` | `{prefix}_http_requests_total` | method, endpoint, status_code |
| `performance` | `{prefix}_http_request_duration_seconds` | method, endpoint |
| `reliability` | `{prefix}_http_errors_total` | method, endpoint, status_class (4xx/5xx) |
| `health` | `{prefix}_http_status_total` | status_code |
| `auth` | `{prefix}_auth_login_attempts_total` | result |
| `auth` | `{prefix}_auth_token_refresh_total` | result |
| `auth` | `{prefix}_auth_logout_total` | — |
| `auth` | `{prefix}_auth_token_validation_failures_total` | reason |
| `auth` | `{prefix}_auth_oauth_attempts_total` | provider, result |

The `auth` group is only meaningful in services that have auth routes.  HTTP-only services
should use `METRICS_GROUPS=traffic,performance,reliability,health`.

Record auth-specific events manually in your route handlers:

```python
from auth_sdk_m8.observability.metrics import get as _get_metrics

def login(...):
    ...
    m = _get_metrics()
    if m and m.login_attempts_total:
        m.login_attempts_total.labels(result="success").inc()
```

### Observability hooks

Attach structured logging, metrics, or tracing via `ValidationHooks`:

```python
import logging
from auth_sdk_m8.security import ValidationHooks

class LogHooks:
    def on_success(self, *, jti: str, sub: str, token_type: str) -> None:
        logging.info("token_ok type=%s sub=%s jti=%s", token_type, sub, jti)

    def on_failure(self, *, reason: str, token_type: str) -> None:
        logging.warning("token_fail type=%s reason=%s", token_type, reason)

validator = TokenValidator(secrets=..., config=..., hooks=LogHooks())
```

Failure reasons: `"expired"`, `"invalid"`, `"wrong_type"`, `"invalid_payload"`, `"revoked"`, `"reused"`.

### Key rotation

Resolve keys dynamically from the JWT `kid` header while keeping verification local:

```python
from auth_sdk_m8.security import KeyResolver, TokenValidationConfig, TokenValidator

class MyResolver(KeyResolver):
    def resolve(self, kid: str | None):
        return lookup_token_secret(kid)

validator = TokenValidator(
    secrets=None,
    config=TokenValidationConfig(),
    key_resolver=MyResolver(),
)
```

### Asymmetric keys (RS256 / ES256)

```python
from pydantic import SecretStr
from auth_sdk_m8.schemas.auth import TokenSecret

# Public key used for verification only — never share the private key with consumers.
ts = TokenSecret(
    secret_key=SecretStr(open("public.pem").read()),
    algorithm="RS256",
)
```
