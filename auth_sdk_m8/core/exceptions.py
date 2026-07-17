"""Custom exceptions for auth-sdk-m8."""


class InvalidToken(Exception):
    """Raised when a JWT token is invalid, expired, or of the wrong type."""


class ConfigurationError(RuntimeError):
    """Fatal application configuration error."""


class ApiKeyCapabilityCeilingError(ValueError):
    """Raised when an API-key capability check requires more than ``WRITER``.

    API-key authorization is capped at ordinary user-domain read/write work;
    administrative and superuser capability are never reachable through an API
    key, whatever the owner's role. Requiring a higher role on an API-key path
    is therefore a programming error the surface rejects rather than a denial
    to report to the caller.

    Carries only a bounded reason code (e.g. ``api_key_capability_ceiling``) as
    its message, so it is always safe to log or surface in observability.
    """


class UnsupportedApiKeySchemaVersionError(ValueError):
    """Raised when an API-key introspection payload declares an unknown version.

    Consumers and the issuer both fail closed on a version they do not
    implement instead of guessing at the payload's meaning.

    Carries only a bounded reason code (e.g.
    ``unsupported_api_key_schema_version``) as its message — never the payload —
    so it is always safe to log or surface in observability.
    """


class InconsistentPrivilegeClaimsError(ValueError):
    """Raised when ``role``/``is_superuser`` violate the canonical truth table.

    Carries only a bounded reason code (e.g. ``inconsistent_privilege_claims``)
    as its message — never the raw role/flag values or token data — so it is
    always safe to log or surface in observability.
    """


class UnsupportedJtiStatusSchemaVersionError(ValueError):
    """Raised when a JTI-status introspection response declares an unknown version.

    Consumers fail closed on a version they do not implement instead of
    guessing at the payload's meaning.

    Carries only a bounded reason code (e.g.
    ``unsupported_jti_status_schema_version``) as its message — never the
    payload — so it is always safe to log or surface in observability.
    """
