"""API-key principal and issuer-introspection contract schemas.

An API key is an opaque bearer *pointer to its owner*, never a credential with
capabilities of its own: it stores no role, so a request is authorized as its
owner, at the owner's **current** role, and can never exceed it. The resolved
principal is what carries role awareness.

The same rule has two implementations — the issuer (``fa-auth-m8``) reads the
owner from its own database, and every other service resolves the same owner
through ``POST /private/v1/api-keys/introspect``, because it does not share
that database. Both return the **one** :class:`ApiKeyPrincipal` defined here
and evaluate it with the same predicates from :mod:`auth_sdk_m8.authorization`,
so the local and remote halves of the rule cannot drift.

This module owns the contract shapes only. Following the JTI-status precedent,
the SDK ships **no HTTP transport** for the introspection call — the client
lives in ``fastapi-m8``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Final, Literal, Optional, Self, Union

from pydantic import BaseModel, Field, SecretStr, model_validator

from auth_sdk_m8.authorization import (
    has_api_key_capability,
    has_minimum_role,
    has_superuser_privileges,
    validate_privilege_claims,
)
from auth_sdk_m8.core.exceptions import UnsupportedApiKeySchemaVersionError
from auth_sdk_m8.schemas.base import ApiKeyAccessMode, RoleType

#: Schema version this SDK release speaks on the introspection contract.
API_KEY_INTROSPECTION_SCHEMA_VERSION: Final[str] = "1"

#: Every version this SDK release can interpret. A payload declaring anything
#: else is refused rather than guessed at — see
#: :func:`validate_api_key_introspection_schema_version`.
SUPPORTED_API_KEY_INTROSPECTION_SCHEMA_VERSIONS: Final[frozenset[str]] = frozenset(
    {API_KEY_INTROSPECTION_SCHEMA_VERSION}
)

#: Bounded, secret-free reason code for the typed version error below.
UNSUPPORTED_API_KEY_SCHEMA_VERSION_REASON = "unsupported_api_key_schema_version"

#: Every principal resolved from an API key reports this authentication method,
#: so a route policy can tell an API-key principal from a JWT one.
API_KEY_AUTHENTICATION_METHOD: Final[str] = "api_key"


def validate_api_key_introspection_schema_version(schema_version: str) -> None:
    """Raise if *schema_version* is not one this SDK release implements.

    The shared fail-closed chokepoint for both ends of the contract: the issuer
    calls it on the requested version (answering ``503`` rather than serving a
    contract it does not implement), and a consumer rejects a response it
    cannot interpret instead of reading unknown fields as an authorization
    result.

    Args:
        schema_version: The version declared on the payload.

    Raises:
        UnsupportedApiKeySchemaVersionError: If the version is unknown. Carries
            only the bounded reason code, never the payload.
    """
    if schema_version not in SUPPORTED_API_KEY_INTROSPECTION_SCHEMA_VERSIONS:
        raise UnsupportedApiKeySchemaVersionError(
            UNSUPPORTED_API_KEY_SCHEMA_VERSION_REASON
        )


class ApiKeyPrincipal(BaseModel):
    """The canonical principal an API key resolves to — one type, both paths.

    Holds the owner's **current** claims as of this decision, narrowed by the
    key's immutable access mode. It is evidence for the request being
    authorized now, never authorization to reuse later: a principal is resolved
    per capability-bearing request and never cached across requests.

    ``is_superuser`` describes the owner's canonical record; it never grants
    superuser authority through an API key (:meth:`has_capability` caps every
    decision at ``WRITER``). ``role`` and ``is_superuser`` must agree per the
    canonical truth table, so an inconsistent owner cannot be represented as a
    principal at all — the issuer answers ``active: false`` for one instead.

    Attributes:
        user_id: The owner's id (UUID as string; the contract is JSON).
        role: The owner's current persisted role.
        is_superuser: The owner's current persisted superuser flag.
        access_mode: The key's immutable operation-category cap.
        authentication_method: Always ``"api_key"``.
        auth_generation: The owner's generation backing this decision.
    """

    user_id: str = Field(min_length=1)
    role: RoleType
    is_superuser: bool = False
    access_mode: ApiKeyAccessMode
    authentication_method: Literal["api_key"] = "api_key"
    auth_generation: int = Field(ge=1)

    @model_validator(mode="after")
    def validate_privilege_claim_consistency(self) -> Self:
        """Reject a ``role``/``is_superuser`` pair outside the truth table.

        Raises:
            InconsistentPrivilegeClaimsError: Wrapped by Pydantic into a
                ``ValidationError`` carrying only the bounded reason code.
        """
        validate_privilege_claims(self.role, self.is_superuser)
        return self

    def has_capability(self, required_role: RoleType) -> bool:
        """Return whether this principal may perform a *required_role* action.

        The only authorization entry point on the principal. Delegates to
        :func:`~auth_sdk_m8.authorization.has_api_key_capability`, so an
        API-key decision is identical wherever it is made.

        Args:
            required_role: The minimum role the operation requires, at most
                ``WRITER``.

        Returns:
            ``True`` only when the owner's role **and** the key's access mode
            both permit the operation.

        Raises:
            ApiKeyCapabilityCeilingError: If *required_role* is above the
                API-key ceiling — administrative and superuser operations are
                JWT-only and must never be gated by an API key.
        """
        return has_api_key_capability(
            self.role, self.is_superuser, self.access_mode, required_role
        )

    def has_minimum_role(self, required_role: RoleType) -> bool:
        """Return whether the **owner's** role meets *required_role*.

        Only the role dimension of the decision, ignoring the key's access-mode
        cap and the API-key ceiling. Use :meth:`has_capability` to authorize a
        request; this is for reporting the owner's standing.

        Args:
            required_role: The role to compare the owner's role against.

        Returns:
            ``True`` if the owner's current role is at least *required_role*.
        """
        return has_minimum_role(self.role, required_role)

    def owner_has_superuser_privileges(self) -> bool:
        """Return whether the **owner** is a canonical superuser.

        A statement about the owner's record, not about this principal's
        authority: an API key never confers superuser or administrative
        capability, whoever owns it. Authorizing on this predicate would be
        exactly the bypass the capability ceiling exists to prevent — use
        :meth:`has_capability`.

        Returns:
            ``True`` only for a consistent, canonical superuser owner.
        """
        return has_superuser_privileges(self.role, self.is_superuser)


class ApiKeyIntrospectionRequest(BaseModel):
    """Request body for the issuer's API-key introspection endpoint.

    Carries the **raw presented key**, held as a :class:`~pydantic.SecretStr`
    so it is masked in ``repr`` and in generic serialization — the credential
    reaches the wire only where the transport deliberately unwraps it. A
    client-generated hash is never accepted: it would be bearer-equivalent and
    would couple every consumer to the issuer's hashing internals.

    The *caller's* own internal-service credential is not part of this body; it
    travels on the private-route headers and is what determines the evaluated
    audience.

    Attributes:
        api_key: The raw API key presented to the calling service.
        schema_version: The contract version the caller speaks. Left
            unvalidated here so the issuer can answer a version it does not
            implement with ``503`` rather than a schema error.
    """

    api_key: SecretStr
    schema_version: str = API_KEY_INTROSPECTION_SCHEMA_VERSION


class ApiKeyIntrospectionResponseBase(BaseModel):
    """Shared version handling for both introspection response shapes."""

    schema_version: str = API_KEY_INTROSPECTION_SCHEMA_VERSION

    @model_validator(mode="after")
    def validate_schema_version(self) -> Self:
        """Reject a response declaring a version this release cannot interpret.

        Raises:
            UnsupportedApiKeySchemaVersionError: Wrapped by Pydantic into a
                ``ValidationError`` carrying only the bounded reason code.
        """
        validate_api_key_introspection_schema_version(self.schema_version)
        return self


class ApiKeyIntrospectionInactiveResponse(ApiKeyIntrospectionResponseBase):
    """The single generic result for every unusable key.

    Unknown, revoked, or expired key; missing, inactive, tombstoned, or
    claim-inconsistent owner; or an audience the key does not carry all return
    **this exact shape**, so a caller cannot probe another account's state. The
    consumer maps it to its own generic client-facing ``401``.
    """

    active: Literal[False] = False


class ApiKeyIntrospectionActiveResponse(ApiKeyIntrospectionResponseBase):
    """A successfully resolved key: the minimized canonical principal.

    An active result is by definition an existing, active, canonical owner, so
    the response repeats no activity state and exposes no owner detail — no
    ``is_active``, key hash, key id, email, or rejection reason.

    Attributes:
        audience_id: The audience the issuer derived from the calling
            consumer's registry identity, never from the request. The consumer
            verifies it matches its own configured identity before use; a
            mismatch is a trusted-configuration failure, not a denial.
        principal: The owner's current authority, narrowed by the key.
        key_expires_at: When the key expires, or ``None`` if it does not.
    """

    active: Literal[True] = True
    audience_id: str = Field(min_length=1)
    principal: ApiKeyPrincipal
    key_expires_at: Optional[datetime] = None


#: Either introspection outcome, discriminated by ``active``.
ApiKeyIntrospectionResponse = Annotated[
    Union[ApiKeyIntrospectionActiveResponse, ApiKeyIntrospectionInactiveResponse],
    Field(discriminator="active"),
]
