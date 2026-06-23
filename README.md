# auth-sdk-m8

![CI/CD](https://github.com/mano8/auth-sdk-m8/actions/workflows/CI.yaml/badge.svg?branch=main)
[![PyPI version](https://img.shields.io/pypi/v/auth-sdk-m8)](https://pypi.org/project/auth-sdk-m8/)
[![Python](https://img.shields.io/pypi/pyversions/auth-sdk-m8)](https://pypi.org/project/auth-sdk-m8/)
[![PyPI Downloads](https://static.pepy.tech/personalized-badge/auth-sdk-m8?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/auth-sdk-m8)
[![codecov](https://codecov.io/gh/mano8/auth-sdk-m8/graph/badge.svg?token=TF6OGIHOGF)](https://codecov.io/gh/mano8/auth-sdk-m8)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/8b8e9726b0f8441ea480902ea8910812)](https://app.codacy.com/gh/mano8/auth-sdk-m8/dashboard?utm_source=gh&utm_medium=referral&utm_content=&utm_campaign=Badge_grade)

Shared authentication schemas, JWT validation, and FastAPI base components for any service that issues or validates JWT tokens. Supports Python 3.11 – 3.14.

Companion SDK to [fa-auth-m8](https://github.com/mano8/fa-auth-m8) — install in any FastAPI service that needs to validate tokens from the fa-auth-m8 authentication service. Provides Pydantic schemas, JWT validation, `CommonSettings`, the fa-auth SSE event-stream bridge client, and optional Prometheus metrics.

---

## Summary

- [Installation](#installation)
- [Secure-by-default (1.0.0)](#secure-by-default-100)
- [Deployment modes](#deployment-modes)
  - [HS256 — symmetric](#hs256--symmetric-opt-in-single-service-or-monolith)
  - [RS256 — issuer side](#rs256--asymmetric-issuer-side-auth_user_service)
  - [RS256 — consumer JWKS](#rs256--asymmetric-consumer-side-jwks-recommended)
  - [RS256 — consumer offline](#rs256--asymmetric-consumer-offline-static-public-key-file)
  - [ES256 — ECDSA](#es256--ecdsa-drop-in-for-rs256)
- [FastAPI integration](#fastapi-integration)
- [Service metadata & liveness routes](#service-metadata--liveness-routes-meta--ping)
- [Startup config validation](#startup-config-validation)
- [Service role](#service-role-auth_service_role)
- [Asymmetric key-strength enforcement](#asymmetric-key-strength-enforcement)
- [Response security headers](#response-security-headers)
- [Strict production mode](#strict-production-mode)
- [Defaults by layer](#defaults-by-layer)
- [Token modes](#token-modes)
- [Chrome extension / native-app OAuth support](#chrome-extension--native-app-oauth-support)
- [Auth degradation policy](#auth-degradation-policy)
- [Issuer / audience enforcement](#issuer--audience-enforcement)
- [Refresh token rotation](#refresh-token-rotation)
- [Observability hooks](#observability-hooks)
- [Prometheus metrics](#prometheus-metrics)
- [Auth event stream (SSE bridge)](#auth-event-stream-sse-bridge)
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
| `[events]` | `httpx` | fa-auth SSE event-stream client |
| `[redis]` | `redis` | JTI blacklist (`AccessTokenBlacklist`) |
| `[db]` | `sqlmodel`, `sqlalchemy` | `TimestampMixin`, DB error parsing |
| `[mysql]` | `pymysql` | MySQL driver |
| `[postgres]` | `psycopg2-binary` | PostgreSQL driver |
| `[observability]` | `prometheus-client`, `fastapi` | Prometheus metrics middleware |
| `[all]` | everything | full feature set |

```bash
pip install "auth-sdk-m8[security,fastapi,config,db,mysql]"
```

---

## Secure-by-default (1.0.0)

**1.0.0 is a breaking release.** The most secure design is now the default; operators opt out via
config. Three defaults changed:

| Finding | Secure default (1.0.0) | Opt-out |
| --- | --- | --- |
| **F2 — algorithm** | `ACCESS_TOKEN_ALGORITHM=RS256` (asymmetric / JWKS) | `ACCESS_TOKEN_ALGORITHM=HS256` (+ `ACCESS_SECRET_KEY`) |
| **F1 — token binding** | `TOKEN_STRICT_VALIDATION=true` — `iss`/`aud` enforced; `TOKEN_ISSUER` + `TOKEN_AUDIENCE` **required at boot** | `TOKEN_STRICT_VALIDATION=false` (single-service/dev) |
| **F3 — event bus** | `EVENT_SIGNING_ENABLED=true` — payloads HMAC-signed; `EVENT_SIGNING_KEY` **required at boot** | `EVENT_SIGNING_ENABLED=false`, or `EVENT_SIGNING_ACCEPT_UNSIGNED=true` during rollout |

A service that relied on the old implicit `HS256` default, or that ran without `TOKEN_ISSUER` /
`TOKEN_AUDIENCE` / `EVENT_SIGNING_KEY`, will now **fail closed at startup** until it either adopts the
secure posture (recommended) or sets the opt-out. Refresh tokens are always `HS256` (internal,
symmetric) and `TOKEN_ALGORITHM` is never propagated to `REFRESH_TOKEN_ALGORITHM`.

**Migrating an existing HS256 / permissive deployment:**

1. Stay on HS256 for now: set `ACCESS_TOKEN_ALGORITHM=HS256`. Move to RS256 when ready (below).
2. Set `TOKEN_ISSUER` and `TOKEN_AUDIENCE` on every service (both issuer and consumers must agree),
   or set `TOKEN_STRICT_VALIDATION=false` if you genuinely have no cross-service boundary.
3. Distribute a shared `EVENT_SIGNING_KEY` to all event-bus publishers and subscribers; roll out
   with `EVENT_SIGNING_ACCEPT_UNSIGNED=true`, then flip it back to `false` once every publisher signs.
   Set `EVENT_SIGNING_ENABLED=false` only if you do not use the event bus.

---

## Deployment modes

| Mode | When to use |
| ---- | ----------- |
| **RS256 / ES256 — JWKS** | **Default.** Multiple independent consumers — each fetches the public key dynamically; recommended for most multi-service setups |
| **RS256 / ES256 — offline** | Air-gapped or embedded deployments where the JWKS endpoint is unreachable |
| **HS256** | Opt-in. Single service or tight monolith — all services share the same secret |

### HS256 — symmetric (opt-in: single-service or monolith)

Every service shares the same secret. Simple to set up; not recommended when consumers are
maintained by different teams. **Since 1.0.0 HS256 is opt-in** — you must set
`ACCESS_TOKEN_ALGORITHM=HS256` explicitly (the default is `RS256`).

#### .env

```ini
ACCESS_TOKEN_ALGORITHM=HS256
ACCESS_SECRET_KEY=your-strong-secret-key
REFRESH_SECRET_KEY=your-strong-refresh-secret
# Strict iss/aud binding is on by default — set both, or opt out:
TOKEN_ISSUER=https://auth.example.com
TOKEN_AUDIENCE=https://api.example.com
# TOKEN_STRICT_VALIDATION=false   # single-service/dev opt-out instead of iss/aud
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
| `ENVIRONMENT=production` with `TOKEN_ISSUER` or `TOKEN_AUDIENCE` unset | warning (fatal under `STRICT_PRODUCTION_MODE`) |
| `ALLOWED_HOSTS` not configured in `ENVIRONMENT=production` | warning |
| `ALLOWED_HOSTS` not configured under `STRICT_PRODUCTION_MODE` | **fatal** |
| `ALLOWED_HOSTS` contains wildcard `'*'` under `STRICT_PRODUCTION_MODE` | **fatal** |
| `JWKS_URI` / `INTROSPECTION_URL` using `http://` in `staging`/`production` | warning (fatal under `STRICT_PRODUCTION_MODE`) |
| `JWKS_URI` / `INTROSPECTION_URL` using `http://` with `ALLOW_INTERNAL_HTTP=true` | allowed (break-glass opt-in) |

---

## Service metadata & liveness routes (`/meta` + `/ping`)

`mount_service_meta` mounts the two standard routes every m8 service should expose, with an
identical shape across the issuer (`fa-auth-m8`) and every consumer. It lives in this platform SDK
because it is the only common dependency of both the issuer and the consumer framework
(`fastapi-m8`). Needs the `fastapi` extra.

| Route | Question | Touches deps? | Cacheable |
| --- | --- | --- | --- |
| `{prefix}/meta` | what version/contract is this service? | no | yes (`Cache-Control`) |
| `{prefix}/ping` | is the process up & serving? | **no** (liveness) | no |

`/meta` is read by clients **pre-auth** to assert compatibility before they do anything else; it
exposes only `service` / `version` / `api_version` / `contract` — never build paths, hostnames,
dependency internals, or secrets. `/ping` is a pure liveness probe — keep it separate from a
dependency-aware `/health` readiness probe so a transient DB/Redis blip cannot trigger a restart.

`/ping` is mounted **once**, at the effective prefix: when `prefix` is set it is served **only** at
`{prefix}/ping` (e.g. `/media/ping`), so it stays reachable behind a prefix-routing reverse proxy
(Traefik forwards only `PathPrefix({prefix})`); when `prefix` is empty it is served at the root
`/ping`. Either way there is a single `ping` operation, and it is **published in the OpenAPI
schema**.

> **Breaking change in 2.0.0.** Before 2.0.0 the root `/ping` was *always* mounted alongside a
> hidden (schema-excluded) `{prefix}/ping` copy. As of 2.0.0 a prefixed service no longer serves the
> root `/ping` — probes must use `{prefix}/ping`. Services with no `API_PREFIX` are unaffected.

```python
from fastapi import FastAPI
from auth_sdk_m8.controllers.meta import mount_service_meta
from auth_sdk_m8.schemas.meta import ServiceContract, ServiceMeta

app = FastAPI()
mount_service_meta(
    app,
    ServiceMeta(
        service="media-service-m8",
        version="1.0.0",
        api_version="v1",
        contract=ServiceContract(
            name="media-service-m8", version="1.0", range=">=1.0.0 <2.0.0"
        ),
    ),
    prefix=settings.API_PREFIX,  # e.g. "/media" → GET /media/meta; "" → GET /meta
)
```

```jsonc
// GET {API_PREFIX}/meta  → 200
{
  "service": "media-service-m8",
  "version": "1.0.0",
  "api_version": "v1",
  "contract": { "name": "media-service-m8", "version": "1.0", "range": ">=1.0.0 <2.0.0" }
}

// GET {API_PREFIX}/ping  → 200   (e.g. /media/ping; root /ping → 404 when a prefix is set)
{ "status": "ok" }
```

**`meta` is a required argument** — a service literally cannot mount the routes without supplying
valid values (provide-or-fail at the call site). Every `ServiceMeta` / `ServiceContract` field is
non-empty (`min_length=1`), so blank values fail validation at construction. The model is pure
Pydantic (no FastAPI import), so non-web SDK users can build/validate meta without the `fastapi`
extra; only `mount_service_meta` needs FastAPI.

> Consumers built on `fastapi-m8` get both routes wired automatically inside `create_app` (sourced
> from `ConsumerServiceSettings`); the issuer `fa-auth-m8` calls `mount_service_meta` directly since
> it does not use the consumer app factory.

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

## Response security headers

`add_security_headers_middleware(app, settings)` attaches hardening headers to every response,
including errors raised before the route handler. It lives in this platform SDK (not `fastapi-m8`),
so the issuer (`fa-auth-m8`) can use it without importing the consumer-only package. It needs
`fastapi` installed — already true for any FastAPI service; install `auth-sdk-m8[fastapi]` only if
pulling it into a context without FastAPI.

```python
from fastapi import FastAPI
from auth_sdk_m8.security.headers import add_security_headers_middleware
from auth_sdk_m8.core.config import CommonSettings

settings = CommonSettings()
app = FastAPI(...)
add_security_headers_middleware(app, settings)
```

Headers are applied in **three tiers** (the whole layer is suppressed when
`SECURITY_HEADERS_ENABLED=false`):

| Header | When applied |
| --- | --- |
| `X-Content-Type-Options: nosniff` | **Always** (every environment) |
| `X-Frame-Options: DENY` | **Always** (every environment) |
| `Referrer-Policy` | Production-gated: `ENVIRONMENT == "production"` or `STRICT_PRODUCTION_MODE` |
| `Permissions-Policy` | Production-gated: `ENVIRONMENT == "production"` or `STRICT_PRODUCTION_MODE` |
| `Strict-Transport-Security` | **Express opt-in only** (`HSTS_ENABLED=true`) — never on local |
| `Content-Security-Policy` | **Express opt-in only** (`CONTENT_SECURITY_POLICY_ENABLED=true`) — never on local |

**Why HSTS and CSP are opt-in, not production-gated.** Both are persisted by the browser and hard
to reverse. HSTS in particular writes a long-lived (`HSTS_MAX_AGE`, default 1 year) HTTPS-only
record for the host — enable it on a stack reachable over plain HTTP or on `localhost` (e.g. while
testing a production-configured build locally) and the browser will force-upgrade `localhost` to
HTTPS and break every local service on that host. So these two headers:

- are **never** inferred from the production gate — you must set `HSTS_ENABLED` /
  `CONTENT_SECURITY_POLICY_ENABLED` explicitly;
- are **never** emitted when `ENVIRONMENT == "local"`, even if you opt in;
- apply independently of `ENVIRONMENT` otherwise (so `staging` with TLS termination can opt in
  without flipping to a production env name). Only enable them behind a TLS-terminating proxy.

The always-on subset is safe everywhere and will not break Swagger/ReDoc or HMR.

**Settings** (via `CommonSettings` or your concrete settings):

| Setting | Default | Description |
| --- | --- | --- |
| `SECURITY_HEADERS_ENABLED` | `True` | Master switch for the whole layer |
| `HSTS_ENABLED` | `False` | Express opt-in for `Strict-Transport-Security` |
| `HSTS_MAX_AGE` | `31536000` | HSTS `max-age` in seconds (`0` also disables it) |
| `HSTS_INCLUDE_SUBDOMAINS` | `True` | Adds `; includeSubDomains` |
| `CONTENT_SECURITY_POLICY_ENABLED` | `False` | Express opt-in for `Content-Security-Policy` |
| `CONTENT_SECURITY_POLICY` | `None` | CSP value; `None` → tight API default (`default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'`) |
| `REFERRER_POLICY` | `"strict-origin-when-cross-origin"` | Referrer policy (production-gated) |
| `PERMISSIONS_POLICY` | `"accelerometer=(), camera=(), …"` | Permissions policy (production-gated) |

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
- `ALLOWED_HOSTS` not configured → **fatal** (base: warning in production only)
- `ALLOWED_HOSTS` contains wildcard `'*'` → **fatal**
- `JWKS_URI` / `INTROSPECTION_URL` using `http://` in `staging`/`production` → **fatal** (base: warning; bypass with `ALLOW_INTERNAL_HTTP=true`)

---

## Defaults by layer

Security-critical settings and how they behave across the stack. **All `secret_fields` reject the
literal `changethis` placeholder at startup** — a service with any modeled secret still at its
placeholder fails closed immediately.

**Boot-required conditions:**

- Any modeled secret field set to `changethis` → `ValueError` at startup; never ship placeholder
  values in a running deployment.
- `EVENT_SIGNING_KEY` is required when `EVENT_SIGNING_ENABLED=true` (the default); boot fails
  without it.
- `TOKEN_ISSUER` and `TOKEN_AUDIENCE` are required when `TOKEN_STRICT_VALIDATION=true` (the
  default); boot fails without them.
- `ACCESS_PUBLIC_KEY_FILE` or `JWKS_URI` is required with `RS256`/`ES256`; no implicit fallback.

| Setting | SDK default | `local` / dev | fa-auth-m8 `hardened_m8` | fastapi-m8 consumer | Production overlay |
| --- | --- | --- | --- | --- | --- |
| `ACCESS_TOKEN_ALGORITHM` | `RS256` | any | `RS256` | `RS256` | `RS256` |
| `TOKEN_STRICT_VALIDATION` | `true` | `true` (iss + aud enforced) | `true` | `true` | `true` |
| `TOKEN_ISSUER` | `None` | optional | set in `auth.env.example` | must match issuer | **required** (strict fatal if unset) |
| `TOKEN_AUDIENCE` | `None` | optional | set in `auth.env.example` | must match issuer | **required** (strict fatal if unset) |
| `EVENT_SIGNING_ENABLED` | `true` | `true` | `true` | inherited | `true` |
| `EVENT_SIGNING_KEY` | `None` | **required** when signing enabled; boot fails without it | `changethis` → fatal at startup | inherited | non-placeholder required |
| `ENVIRONMENT` | `local` | `local` | `local` | `local` | `production` (overlay) |
| `STRICT_PRODUCTION_MODE` | `false` | `false` | `false` | `false` | `true` (overlay) |
| `ALLOWED_HOSTS` | `None` | no host check | `None` — Traefik host rules are primary in this stack | `None` | **required**; strict fatal if unset |
| `ALLOWED_ORIGINS` | `["http://localhost:8080"]` | any | localhost allowed | localhost allowed | no `localhost` (prod fatal) |
| `SET_DOCS` / `SET_OPEN_API` | `true` | on | on | on | **off** (gated in production) |
| `SERVE_DOCS_IN_PRODUCTION` | `false` | N/A | N/A | N/A | explicit opt-in to publish docs in prod |
| `HSTS_ENABLED` | `false` | never (local-blocked) | never | never | **opt-in only** (`HSTS_ENABLED=true`); never automatic |
| `CONTENT_SECURITY_POLICY_ENABLED` | `false` | never (local-blocked) | never | never | **opt-in only**; never automatic |
| `SESSION_COOKIE_SECURE` | `false` | `false` | `false` | N/A | `true` (overlay) |
| `ALLOW_INTERNAL_HTTP` | `false` | no check in `local` | Docker-network-only (single trusted host) | Docker-network-only | `true` opt-in (single trusted Docker host) |
| `AUTH_STRICT_MODE` | `false` | `false` | `false` | `false` | optionally `true` for fail-closed Redis ops |

> **HSTS and CSP are never inferred from the production flag.** Both are browser-persisted and
> hard to reverse; enabling either on a plain-HTTP or localhost stack breaks the browser for that
> host. Set `HSTS_ENABLED=true` / `CONTENT_SECURITY_POLICY_ENABLED=true` only when the stack is
> behind a TLS-terminating proxy in a non-local environment. The production overlay documents these
> as opt-in only.

**fa-auth-m8 compose examples — dev vs production-capable:**

| Example | Purpose |
| --- | --- |
| `quickstart_m8` | **Dev-only** — SQLite, no Redis, HS256 out of the box |
| `postgres_m8` | **Dev-only** — PostgreSQL, stateful tokens, no hardening layer |
| `rs256_m8` | **Dev-only** — RS256 key-pair demo, single service |
| `metrics_m8` | **Dev-only** — Prometheus + Grafana observability |
| `vault_dev_m8` | **Dev-only** — HashiCorp Vault in dev mode (root token); never point a production app at it |
| `hardened_m8` | Dev + production-capable via `docker-compose.production.yml` overlay |

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
| `ALLOWED_HOSTS` | `None` | Comma-separated list of accepted `Host` header values for Starlette `TrustedHostMiddleware`. `None` disables host-header checking. Checked at startup by `check_config_health`: missing in production → warning; missing under `STRICT_PRODUCTION_MODE` or containing `'*'` under strict → fatal. |
| `ALLOW_INTERNAL_HTTP` | `False` | Break-glass opt-in: allow `JWKS_URI` and `INTROSPECTION_URL` to use plain `http://` in staging/production when all inter-service traffic is confined to a trusted internal Docker network. Without this flag, `http://` in those fields produces a warning in staging/production and a fatal in strict mode. |

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

**Since 1.0.0 strict binding is on by default** (`TOKEN_STRICT_VALIDATION=true`):
`build_access_validator` enforces `iss` **and** `aud`, and `CommonSettings` **requires both
`TOKEN_ISSUER` and `TOKEN_AUDIENCE`** at startup — a service without them fails closed at boot.
Tokens with a wrong or missing `iss`/`aud` are rejected.

Single-service or dev deployments that genuinely have no cross-service boundary opt out with
`TOKEN_STRICT_VALIDATION=false`, which restores the permissive profile (claims enforced only when
`TOKEN_ISSUER` / `TOKEN_AUDIENCE` are set).

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
| `performance` | `http_request_duration_seconds` histogram (method, endpoint) |
| `reliability` | `http_errors_total` (method, endpoint, status_class) |
| `health` | `http_status_total` by exact status code |
| `auth` | `auth_login_attempts_total` (result: success\|wrong_credentials\|inactive_user\|rate_limited), `auth_token_refresh_total` (result: success\|invalid\|revoked\|rate_limited), `auth_logout_total`, `auth_token_validation_failures_total` (reason: invalid\|revoked\|inactive), `auth_oauth_attempts_total` (provider, result: success\|failed), `auth_code_exchange_total` (result: success\|expired_or_invalid\|pkce_failed\|redis_unavailable), `auth_revocation_failure_total` (operation: access_blacklist\|refresh_allowlist\|db_session), `auth_degraded_decision_total` (control, mode, reason), `auth_redis_circuit_breaker_open` (gauge: 0=closed 1=open), `auth_degradation_mode_active` (gauge per control+mode), `auth_session_integrity_denial_total` (trigger: reuse_detected), `auth_api_key_validations_total` (result: success\|invalid\|revoked\|expired), `auth_api_key_rate_limit_checks_total` (result: allowed\|blocked), `auth_api_key_rate_limit_hits_total` (period: minute\|hour\|day\|month), `auth_api_key_lifecycle_total` (action: created\|revoked), `auth_api_key_flush_duration_seconds` (histogram) |

> Metric names are prefixed with the normalised `API_PREFIX` passed to `metrics.setup()` (e.g. `/user` → `user_auth_login_attempts_total`), so each service's metrics never collide.

---

## Auth event stream (SSE bridge)

**The chosen transport for auth-state events in the m8 fleet** is an authenticated
Server-Sent Events stream on fa-auth's private API.

Install the `events` extra:

```bash
pip install "auth-sdk-m8[events]"
```

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
from auth_sdk_m8.events import AuthEventStreamClient, AuthStreamEvent, derive_stream_url

client = AuthEventStreamClient(
    stream_url=derive_stream_url(settings.INTROSPECTION_URL),  # e.g. http://fa-auth:8000/private/v1/events/stream
    private_api_secret=settings.PRIVATE_API_SECRET.get_secret_value(),
    signing_key=settings.EVENT_SIGNING_KEY.get_secret_value(),
    on_event=handle_auth_event,
    on_gap=flush_local_caches,
)

async def handle_auth_event(event: AuthStreamEvent) -> None:
    if event.event_type == "session-revoked":
        await cache.evict(event.payload.get("jti"))
    elif event.event_type == "user-deleted":
        await cache.evict_user(event.payload.get("user_id"))

async def flush_local_caches() -> None:
    """Called when a resume gap is unresumable — flush all cached state."""
    await cache.flush_all()

@asynccontextmanager
async def lifespan(app: FastAPI):
    client.start()
    yield
    await client.stop()
```

The client:

- Authenticates with `X-Internal-Token: <PRIVATE_API_SECRET>` (same header used by `jti-status`).
- Verifies every `data` frame with HMAC-SHA256 (`EVENT_SIGNING_KEY`); forged/unsigned events are dropped.
- Reconnects automatically with jittered exponential back-off; sends `Last-Event-ID` for resume.
- Calls `on_gap()` when the server signals an unresumable gap (epoch change or buffer eviction) —
  the caller **must** flush all locally cached validation state.
- Push is a **best-effort accelerator**: the JTI blacklist behind `POST /private/v1/jti-status`
  remains the revocation authority. A missed event is safe (just slower to converge).

`derive_stream_url(introspection_url)` strips `/jti-status` from `INTROSPECTION_URL` and appends
`/events/stream`.

---

## Package layout

```text
auth_sdk_m8/
├── schemas/
│   ├── auth.py          # TokenUserData, TokenAccessData, TokenSecret, ASYMMETRIC_ALGORITHMS
│   ├── base.py          # AuthProviderType, RoleType, Period, response models
│   ├── shared.py        # ValidationConstants (regex patterns)
│   ├── meta.py          # ServiceMeta, ServiceContract (pure Pydantic, no FastAPI)
│   ├── user.py          # UserModel, SessionModel
│   └── user_events.py   # UserDeletedEvent, SessionRevokedEvent
├── events/              # fa-auth SSE bridge client (pip install "auth-sdk-m8[events]")
│   ├── stream_client.py # AuthEventStreamClient, AuthStreamEvent, derive_stream_url
│   └── _signing.py      # canonical-JSON HMAC-SHA256 sign/verify for stream events
├── core/
│   ├── config.py        # CommonSettings, SecretProvider (re-exports check_config_health)
│   ├── config_health.py # check_config_health — startup validation checks
│   ├── consumer.py      # ConsumerAuthMixin — consumer introspection settings
│   ├── exceptions.py    # InvalidToken, ConfigurationError
│   └── security.py      # ComSecurityHelper (legacy: PKCE, token hashing)
├── security/
│   ├── factory.py            # build_access_validator() — settings-driven factory
│   ├── guards.py             # make_internal_token_authorizer, make_scrape_credential_guard, make_consumer_authorizer
│   ├── consumer_auth.py      # ConsumerScope, ConsumerCredential, ConsumerCredentialRegistry (Phase 9.1)
│   ├── headers.py            # add_security_headers_middleware, build_security_headers
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
├── controllers/
│   ├── base.py           # BaseController: exception → JSONResponse
│   └── meta.py           # mount_service_meta — /meta + /ping routes
├── models/
│   └── shared.py         # TimestampMixin, Message, Token, TokenPayload
└── utils/
    ├── email.py          # normalize_email
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
