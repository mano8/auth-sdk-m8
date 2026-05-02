# auth-sdk-m8

Shared authentication schemas, JWT utilities, and FastAPI base components for **m8 microservices**.

This package is extracted from `auth_user_service` and is intended to be installed by any service
that integrates with it via Docker Compose. It provides the Pydantic schemas matching the auth
service's API, JWT validation helpers, and optional FastAPI/SQLModel base classes.

---

## Installation

### From GitLab Package Registry (recommended after first publish)

```bash
pip install auth-sdk-m8 \
  --index-url https://gitlab.com/api/v4/projects/<PROJECT_ID>/packages/pypi/simple \
  --extra-index-url https://pypi.org/simple
```

With a deploy token in `pip.conf` or `~/.netrc`:
```ini
# pip.conf
[global]
index-url = https://gitlab.com/api/v4/projects/<PROJECT_ID>/packages/pypi/simple
extra-index-url = https://pypi.org/simple
```

### Directly from GitLab via git

```bash
pip install "auth-sdk-m8 @ git+https://gitlab.com/yourorg/auth-sdk-m8.git@v0.1.0"
```

### For development (editable install)

```bash
git clone https://gitlab.com/yourorg/auth-sdk-m8.git
cd auth-sdk-m8
pip install -e ".[all,dev]"
```

---

## Optional dependency groups

Install only what your service needs:

| Extra | Installs | Use when |
|---|---|---|
| *(none)* | `pydantic`, `email-validator` | schemas only |
| `[security]` | `PyJWT` | local JWT validation |
| `[fastapi]` | `fastapi` | cookie helpers, `BaseController` |
| `[redis]` | `redis` | Redis event bus |
| `[config]` | `pydantic-settings` | `CommonSettings` base class |
| `[db]` | `sqlmodel`, `sqlalchemy` | `TimestampMixin`, DB error parsing |
| `[all]` | everything above | full feature set |

Examples:

```bash
# A service that only validates tokens locally
pip install "auth-sdk-m8[security]"

# A FastAPI service using BaseController and JWT
pip install "auth-sdk-m8[security,fastapi,db]"

# A service that only listens to Redis events
pip install "auth-sdk-m8[redis]"
```

---

## Quick start

### Validate a JWT from auth_user_service

```python
from auth_sdk_m8.core.security import ComSecurityHelper
from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.auth import TokenDecodeProps
from pydantic import SecretStr

try:
    user = ComSecurityHelper.decode_access_token(
        TokenDecodeProps(
            access_token=bearer_token,
            secret_key=SecretStr(ACCESS_SECRET_KEY),
            algorithm="HS256",
        )
    )
    print(user.email, user.role)
except InvalidToken:
    # token expired or invalid signature
    ...
```

### FastAPI dependency for token validation

```python
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from auth_sdk_m8.core.security import ComSecurityHelper
from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.auth import TokenDecodeProps
from auth_sdk_m8.schemas.user import UserModel
from pydantic import SecretStr

oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/login/access-token")

def get_current_user(token: str = Depends(oauth2)) -> UserModel:
    try:
        payload = ComSecurityHelper.decode_access_token(
            TokenDecodeProps(
                access_token=token,
                secret_key=SecretStr(settings.ACCESS_SECRET_KEY),
                algorithm=settings.TOKEN_ALGORITHM,
            )
        )
    except InvalidToken as exc:
        raise HTTPException(status_code=403, detail="Could not validate credentials.") from exc
    return UserModel(id=payload.sub, **payload.model_dump(exclude={"sub", "jti", "exp", "type"}))
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

```
src/auth_sdk_m8/
├── schemas/
│   ├── auth.py          # JWT payload schemas (TokenUserData, TokenAccessData, …)
│   ├── base.py          # Enums (AuthProviderType, RoleType, Period) + response models
│   ├── shared.py        # ValidationConstants (regex patterns)
│   ├── user.py          # UserModel, SessionModel
│   ├── redis_events.py  # EventBase
│   └── user_events.py   # UserDeletedEvent
├── core/
│   ├── config.py        # CommonSettings (pydantic-settings base class)
│   ├── exceptions.py    # InvalidToken
│   └── security.py      # ComSecurityHelper: JWT decode, PKCE, token hashing
├── redis_events/
│   ├── event_bus.py     # EventBus (typed pub/sub)
│   ├── publisher.py     # EventPublisher
│   └── subscriber.py    # EventSubscriber
├── controllers/
│   └── base.py          # BaseController: unified exception → JSONResponse
├── models/
│   └── shared.py        # TimestampMixin, Message, Token, TokenPayload (SQLModel)
└── utils/
    ├── errors_parser.py # parse_integrity_error, parse_pydantic_errors
    └── paths.py         # find_dotenv
```

---

## Publishing a new version

1. Bump `version` in `pyproject.toml`
2. Add an entry to `CHANGELOG.md`
3. Commit and push
4. Create a git tag: `git tag v0.2.0 && git push origin v0.2.0`
5. GitLab CI builds and publishes automatically to the Package Registry

---

## Architecture note

This SDK is intentionally thin. It contains **no business logic** — only schemas,
validation helpers, and infrastructure base classes. Each consuming service validates
JWTs locally using `ComSecurityHelper` (no network call per request). The `auth_user_service`
remains the sole authority for issuing tokens; this SDK only provides the tools to
**read** them.

For production deployments with multiple teams, consider switching to **RS256** asymmetric
signing so consuming services only need the public key (never the secret).
