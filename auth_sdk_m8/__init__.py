"""auth-sdk-m8 shared authentication utilities for m8 microservices."""

from auth_sdk_m8.authorization import (
    has_minimum_role,
    has_superuser_privileges,
    privilege_claims_are_consistent,
    validate_privilege_claims,
)
from auth_sdk_m8.core.exceptions import InconsistentPrivilegeClaimsError

__version__ = "2.1.1"

__all__ = [
    "__version__",
    "has_minimum_role",
    "has_superuser_privileges",
    "privilege_claims_are_consistent",
    "validate_privilege_claims",
    "InconsistentPrivilegeClaimsError",
]
