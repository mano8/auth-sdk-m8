# auth-sdk-m8

## Layer

Platform: shared authentication SDK.

## Purpose

Provide shared authentication primitives for `fa-auth-m8`, `fastapi-m8`, and
other JWT services.

## Repository boundaries

- Remain framework-agnostic where practical.
- Do not contain business logic from consuming services.
- Do not own a database.
- Provide only reusable authentication and security primitives.

## Local context

Use this file, `pyproject.toml`, repository documentation, and existing CI as
the authoritative local context. Workspace enhancement, when explicitly and
verifiably available, is optional and does not make a parent workspace a
requirement.
