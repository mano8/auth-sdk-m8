"""Custom exceptions for auth-sdk-m8."""


class InvalidToken(Exception):
    """Raised when a JWT token is invalid, expired, or of the wrong type."""


class ConfigurationError(RuntimeError):
    """Fatal application configuration error."""


class InconsistentPrivilegeClaimsError(ValueError):
    """Raised when ``role``/``is_superuser`` violate the canonical truth table.

    Carries only a bounded reason code (e.g. ``inconsistent_privilege_claims``)
    as its message — never the raw role/flag values or token data — so it is
    always safe to log or surface in observability.
    """
