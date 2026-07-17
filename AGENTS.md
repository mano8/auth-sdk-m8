# auth-sdk-m8

## Layer
Platform (shared authentication SDK)

---

## Purpose
Shared auth primitives used by:
- fa-auth-m8
- fastapi services
- microservices templates

---

## Rules
- Must remain framework-agnostic where possible
- No business logic from consuming services
- No database ownership
- Only reusable auth/security primitives

---

## Authority
All rules come from /.workspace/policy.index.json (type: python)


