"""auth-sdk-m8 shared authentication utilities for m8 microservices."""

from auth_sdk_m8.authorization import (
    API_KEY_CAPABILITY_CEILING_REASON,
    API_KEY_MAX_REQUIRED_ROLE,
    INCONSISTENT_PRIVILEGE_CLAIMS_REASON,
    api_key_capability_requires_write,
    find_inconsistent_privilege_claims_error,
    has_api_key_capability,
    has_minimum_role,
    has_superuser_privileges,
    privilege_claims_are_consistent,
    validate_api_key_required_role,
    validate_privilege_claims,
)
from auth_sdk_m8.core.exceptions import (
    ApiKeyCapabilityCeilingError,
    FixtureChecksumMismatchError,
    InconsistentPrivilegeClaimsError,
    UnsupportedApiKeySchemaVersionError,
    UnsupportedFixtureMatrixSchemaVersionError,
    UnsupportedJtiStatusSchemaVersionError,
)
from auth_sdk_m8.schemas.api_key import (
    API_KEY_AUTHENTICATION_METHOD,
    API_KEY_INTROSPECTION_SCHEMA_VERSION,
    SUPPORTED_API_KEY_INTROSPECTION_SCHEMA_VERSIONS,
    UNSUPPORTED_API_KEY_SCHEMA_VERSION_REASON,
    ApiKeyIntrospectionActiveResponse,
    ApiKeyIntrospectionInactiveResponse,
    ApiKeyIntrospectionRequest,
    ApiKeyIntrospectionResponse,
    ApiKeyPrincipal,
    validate_api_key_introspection_schema_version,
)
from auth_sdk_m8.schemas.base import ApiKeyAccessMode
from auth_sdk_m8.schemas.jti_status import (
    JTI_STATUS_SCHEMA_VERSION,
    SUPPORTED_JTI_STATUS_SCHEMA_VERSIONS,
    UNSUPPORTED_JTI_STATUS_SCHEMA_VERSION_REASON,
    JtiStatusActiveResponse,
    JtiStatusInactiveResponse,
    JtiStatusResponse,
    validate_jti_status_schema_version,
)
from auth_sdk_m8.testing import (
    FIXTURE_MATRIX_CHECKSUM_MISMATCH_REASON,
    FIXTURE_MATRIX_SCHEMA_VERSION,
    UNSUPPORTED_FIXTURE_MATRIX_SCHEMA_VERSION_REASON,
    load_authorization_fixture_matrix,
)

__version__ = "3.2.0"

__all__ = [
    "__version__",
    "INCONSISTENT_PRIVILEGE_CLAIMS_REASON",
    "find_inconsistent_privilege_claims_error",
    "has_minimum_role",
    "has_superuser_privileges",
    "privilege_claims_are_consistent",
    "validate_privilege_claims",
    "InconsistentPrivilegeClaimsError",
    # API-key principal + introspection contract
    "API_KEY_AUTHENTICATION_METHOD",
    "API_KEY_CAPABILITY_CEILING_REASON",
    "API_KEY_INTROSPECTION_SCHEMA_VERSION",
    "API_KEY_MAX_REQUIRED_ROLE",
    "SUPPORTED_API_KEY_INTROSPECTION_SCHEMA_VERSIONS",
    "UNSUPPORTED_API_KEY_SCHEMA_VERSION_REASON",
    "ApiKeyAccessMode",
    "ApiKeyCapabilityCeilingError",
    "ApiKeyIntrospectionActiveResponse",
    "ApiKeyIntrospectionInactiveResponse",
    "ApiKeyIntrospectionRequest",
    "ApiKeyIntrospectionResponse",
    "ApiKeyPrincipal",
    "UnsupportedApiKeySchemaVersionError",
    "api_key_capability_requires_write",
    "has_api_key_capability",
    "validate_api_key_introspection_schema_version",
    "validate_api_key_required_role",
    # JTI-status v2 introspection response contract
    "JTI_STATUS_SCHEMA_VERSION",
    "SUPPORTED_JTI_STATUS_SCHEMA_VERSIONS",
    "UNSUPPORTED_JTI_STATUS_SCHEMA_VERSION_REASON",
    "JtiStatusActiveResponse",
    "JtiStatusInactiveResponse",
    "JtiStatusResponse",
    "UnsupportedJtiStatusSchemaVersionError",
    "validate_jti_status_schema_version",
    # Canonical authorization fixture matrix (SDK fixture ownership, §5.5)
    "FIXTURE_MATRIX_CHECKSUM_MISMATCH_REASON",
    "FIXTURE_MATRIX_SCHEMA_VERSION",
    "UNSUPPORTED_FIXTURE_MATRIX_SCHEMA_VERSION_REASON",
    "FixtureChecksumMismatchError",
    "UnsupportedFixtureMatrixSchemaVersionError",
    "load_authorization_fixture_matrix",
]
