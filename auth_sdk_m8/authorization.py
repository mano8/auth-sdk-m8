"""Framework-neutral role/flag authorization primitives.

Canonical role/flag truth table (one row per valid state)::

    role         is_superuser=false   is_superuser=true
    USER         valid, non-superuser invalid
    READER       valid, non-superuser invalid
    WRITER       valid, non-superuser invalid
    ADMIN        valid, non-superuser invalid
    SUPERADMIN   invalid              valid superuser

No caller may derive an authorization decision from ``role`` alone or
``is_superuser`` alone — the two claims must agree. This module is the single
place that encodes the hierarchy and the cross-field invariant so every
consumer (token issuance, token validation, ``UserModel``, framework guards)
shares one implementation.
"""

from __future__ import annotations

from typing import Final

from pydantic import ValidationError

from auth_sdk_m8.core.exceptions import (
    ApiKeyCapabilityCeilingError,
    InconsistentPrivilegeClaimsError,
)
from auth_sdk_m8.schemas.base import ApiKeyAccessMode, RoleType

#: Bounded, secret-free reason code for the typed validation error below.
INCONSISTENT_PRIVILEGE_CLAIMS_REASON = "inconsistent_privilege_claims"

#: Bounded, secret-free reason code for the API-key capability ceiling error.
API_KEY_CAPABILITY_CEILING_REASON = "api_key_capability_ceiling"

#: The highest role an API-key path may ever require. API-key authorization is
#: capped at ordinary user-domain read/write operations; user administration,
#: role assignment, and every other security-sensitive platform operation are
#: JWT-only, so no API-key dependency may require ``ADMIN`` or ``SUPERADMIN``.
API_KEY_MAX_REQUIRED_ROLE: Final[RoleType] = RoleType.WRITER


def has_minimum_role(current_role: RoleType, required_role: RoleType) -> bool:
    """Return whether *current_role* meets or exceeds *required_role*.

    Canonical role hierarchy check, ordered highest to lowest privilege via
    :meth:`RoleType.get_ordered_roles`. This is the single implementation of
    the hierarchy; no consumer should duplicate a role-ordered list.

    Args:
        current_role: The role held by the caller.
        required_role: The minimum role required for the operation.

    Returns:
        ``True`` if *current_role* is at least as privileged as
        *required_role*; ``False`` for an insufficient or unrecognised role.
    """
    ordered = RoleType.get_ordered_roles()
    try:
        return ordered.index(current_role.value) <= ordered.index(required_role.value)
    except ValueError:
        return False


def privilege_claims_are_consistent(role: RoleType, is_superuser: bool) -> bool:
    """Return whether *role* and *is_superuser* agree per the truth table.

    Pure cross-field invariant, independent of any hierarchy comparison:

    - ``role == SUPERADMIN`` requires ``is_superuser is True``.
    - Every other role requires ``is_superuser is False``.

    Args:
        role: The claimed/persisted role.
        is_superuser: The claimed/persisted superuser flag.

    Returns:
        ``True`` only when the pair is one of the five valid rows.
    """
    if role == RoleType.SUPERADMIN:
        return is_superuser is True
    return is_superuser is False


def has_superuser_privileges(role: RoleType, is_superuser: bool) -> bool:
    """Return the exact dual-evidence canonical-superuser predicate.

    Requires both the consistency invariant and the canonical pair
    (``role == SUPERADMIN`` and ``is_superuser is True``). Callers must use
    this instead of checking ``is_superuser`` or ``role`` alone — a stray
    ``is_superuser=true`` on a non-``SUPERADMIN`` role (or vice versa) never
    grants superuser privileges.

    Args:
        role: The claimed/persisted role.
        is_superuser: The claimed/persisted superuser flag.

    Returns:
        ``True`` only for a consistent, canonical superuser pair.
    """
    return (
        privilege_claims_are_consistent(role, is_superuser)
        and role == RoleType.SUPERADMIN
        and is_superuser is True
    )


def validate_privilege_claims(role: RoleType, is_superuser: bool) -> None:
    """Raise if *role*/*is_superuser* violate the canonical truth table.

    Reusable validation chokepoint for token payload creation, token
    validation, and model construction, so all three reject the same bad
    pair. Never logs or embeds the raw claim values — only the bounded
    reason code travels with the error, so callers can safely log/observe it
    without risking token or claim data.

    Args:
        role: The claimed/persisted role.
        is_superuser: The claimed/persisted superuser flag.

    Raises:
        InconsistentPrivilegeClaimsError: If the pair is not one of the five
            valid rows of the canonical truth table.
    """
    if not privilege_claims_are_consistent(role, is_superuser):
        raise InconsistentPrivilegeClaimsError(INCONSISTENT_PRIVILEGE_CLAIMS_REASON)


def find_inconsistent_privilege_claims_error(
    error: ValidationError,
) -> InconsistentPrivilegeClaimsError | None:
    """Return the privilege-claim mismatch inside *error*, if it caused it.

    Models applying the invariant (``UserPayloadData`` and its token
    subclasses, ``UserModel``) raise
    :class:`InconsistentPrivilegeClaimsError` from a model validator, so
    Pydantic reports it as a ``ValidationError`` like any other field problem.
    This lets a caller tell "the claims contradict each other" apart from
    "the payload is malformed" and map only the former to its own boundary
    (e.g. ``TokenValidator`` -> ``InvalidToken`` with the bounded reason).

    The returned error carries only the bounded reason code, so it is safe to
    log or chain. The *error* argument is not — a ``ValidationError`` embeds
    the raw input — so this reads it with input and URLs excluded and never
    surfaces it.

    Args:
        error: The Pydantic error raised while building such a model.

    Returns:
        The typed mismatch error, or ``None`` when *error* was caused by
        anything else.
    """
    for detail in error.errors(
        include_url=False, include_context=True, include_input=False
    ):
        cause = (detail.get("ctx") or {}).get("error")
        if isinstance(cause, InconsistentPrivilegeClaimsError):
            return cause
    return None


# ── API-key capability ───────────────────────────────────────────────────────


def api_key_capability_requires_write(required_role: RoleType) -> bool:
    """Return whether *required_role* is a write capability for an API key.

    Requiring ``WRITER`` (the API-key ceiling) is the write capability;
    anything below it is a read capability. This is the single definition of
    that boundary, so the key's access-mode cap is applied to the same set of
    operations everywhere.

    Args:
        required_role: The minimum role the operation requires.

    Returns:
        ``True`` when the operation needs write authority.
    """
    return has_minimum_role(required_role, RoleType.WRITER)


def validate_api_key_required_role(required_role: RoleType) -> None:
    """Raise if *required_role* exceeds the API-key capability ceiling.

    An API key never carries administrative or superuser authority — not from
    its owner's role, not from ``is_superuser``, and not by configuration — so
    requiring more than :data:`API_KEY_MAX_REQUIRED_ROLE` on an API-key path is
    a programming error rather than a denial. Raising here (instead of
    returning ``False``) keeps that mistake from being read as a routine
    authorization failure and silently shipped.

    Args:
        required_role: The minimum role the operation requires.

    Raises:
        ApiKeyCapabilityCeilingError: If *required_role* is above the ceiling.
    """
    if not has_minimum_role(API_KEY_MAX_REQUIRED_ROLE, required_role):
        raise ApiKeyCapabilityCeilingError(API_KEY_CAPABILITY_CEILING_REASON)


def has_api_key_capability(
    role: RoleType,
    is_superuser: bool,
    access_mode: ApiKeyAccessMode,
    required_role: RoleType,
) -> bool:
    """Return whether an API-key principal may perform a *required_role* action.

    The single authorization decision for **both** API-key paths — the issuer's
    local database read and a consumer's remote introspection result — so the
    two implementations of the same rule cannot drift. Effective authority is
    the intersection of independent narrowing dimensions, each able only to
    narrow:

    1. the ceiling — never administrative or superuser
       (:func:`validate_api_key_required_role`);
    2. the owner's canonical claims — an inconsistent pair grants nothing;
    3. the owner's **current** role, via :func:`has_minimum_role`, so a
       downgrade takes effect on the key's next request;
    4. the key's immutable ``access_mode`` — a write capability additionally
       demands ``READ_WRITE``.

    Args:
        role: The owner's current persisted role.
        is_superuser: The owner's current persisted superuser flag.
        access_mode: The key's immutable access mode.
        required_role: The minimum role the operation requires, at most
            :data:`API_KEY_MAX_REQUIRED_ROLE`.

    Returns:
        ``True`` only when every dimension permits the operation.

    Raises:
        ApiKeyCapabilityCeilingError: If *required_role* is above the ceiling.
    """
    validate_api_key_required_role(required_role)
    if not privilege_claims_are_consistent(role, is_superuser):
        return False
    if not has_minimum_role(role, required_role):
        return False
    if api_key_capability_requires_write(required_role):
        return access_mode == ApiKeyAccessMode.READ_WRITE
    return True
