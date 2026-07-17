"""JTI-status introspection **v2** response contract schemas.

The private ``/private/v1/jti-status`` decision is database-authoritative
(3.5.2): a session/JTI is either an active, canonical, current-generation
subject, or it is not. The v2 response is additive over v1 — it exists so a
consumer can tag its cache entries with the owner's ``auth_generation`` — and
stays minimized: every inactive cause (never-issued, revoked, expired,
tombstoned, inconsistent owner, subject mismatch, stale generation) returns
the **same** generic shape, so the endpoint can never be used as an
account-state or JTI-validity enumeration oracle.

This module owns the response contract shapes only, mirroring the API-key
introspection precedent in :mod:`auth_sdk_m8.schemas.api_key`: the SDK ships
no HTTP transport for the call.
"""

from __future__ import annotations

from typing import Annotated, Final, Literal, Self, Union

from pydantic import BaseModel, Field, model_validator

from auth_sdk_m8.core.exceptions import UnsupportedJtiStatusSchemaVersionError

#: Schema version this SDK release speaks on the v2 JTI-status contract.
JTI_STATUS_SCHEMA_VERSION: Final[str] = "2"

#: Every version this SDK release can interpret. A response declaring
#: anything else is refused rather than guessed at — see
#: :func:`validate_jti_status_schema_version`. The legacy v1 response carries
#: no ``schema_version`` field at all, so it is not a member of this set.
SUPPORTED_JTI_STATUS_SCHEMA_VERSIONS: Final[frozenset[str]] = frozenset(
    {JTI_STATUS_SCHEMA_VERSION}
)

#: Bounded, secret-free reason code for the typed version error below.
UNSUPPORTED_JTI_STATUS_SCHEMA_VERSION_REASON = "unsupported_jti_status_schema_version"


def validate_jti_status_schema_version(schema_version: str) -> None:
    """Raise if *schema_version* is not one this SDK release implements.

    The shared fail-closed chokepoint for the v2 JTI-status response: a
    consumer rejects a response it cannot interpret instead of reading
    unknown fields as an authorization result.

    Args:
        schema_version: The version declared on the payload.

    Raises:
        UnsupportedJtiStatusSchemaVersionError: If the version is unknown.
            Carries only the bounded reason code, never the payload.
    """
    if schema_version not in SUPPORTED_JTI_STATUS_SCHEMA_VERSIONS:
        raise UnsupportedJtiStatusSchemaVersionError(
            UNSUPPORTED_JTI_STATUS_SCHEMA_VERSION_REASON
        )


class JtiStatusResponseBase(BaseModel):
    """Shared version handling for both v2 JTI-status response shapes."""

    schema_version: str = JTI_STATUS_SCHEMA_VERSION

    @model_validator(mode="after")
    def validate_schema_version(self) -> Self:
        """Reject a response declaring a version this release cannot interpret.

        Raises:
            UnsupportedJtiStatusSchemaVersionError: Wrapped by Pydantic into a
                ``ValidationError`` carrying only the bounded reason code.
        """
        validate_jti_status_schema_version(self.schema_version)
        return self


class JtiStatusInactiveResponse(JtiStatusResponseBase):
    """The single generic result for every unusable JTI.

    Never-issued, revoked, expired, tombstoned, subject-mismatched,
    inconsistent-owner, and stale-generation all return **this exact shape**,
    so a caller cannot probe another subject's account state or use the
    endpoint as a JTI-validity enumeration oracle.
    """

    active: Literal[False] = False


class JtiStatusActiveResponse(JtiStatusResponseBase):
    """A confirmed-active session: the minimized cache-tagging shape.

    Returned only when the asserted subject matches a current session backed
    by a canonical, current-generation owner. Carries no role/privilege
    claims, email, or any PII beyond the opaque ``user_id`` the caller already
    asserted from the JWT it legitimately holds.

    Attributes:
        user_id: The session owner's id, echoing the caller's asserted
            subject (never a general JTI-to-user lookup result).
        auth_generation: The owner's generation backing this decision. Opaque
            and monotonic; used solely by the consumer to tag cache entries.
    """

    active: Literal[True] = True
    user_id: str = Field(min_length=1)
    auth_generation: int = Field(ge=1)


#: Either v2 JTI-status outcome, discriminated by ``active``.
JtiStatusResponse = Annotated[
    Union[JtiStatusActiveResponse, JtiStatusInactiveResponse],
    Field(discriminator="active"),
]
