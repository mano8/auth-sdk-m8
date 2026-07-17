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

from auth_sdk_m8.core.exceptions import InconsistentPrivilegeClaimsError
from auth_sdk_m8.schemas.base import RoleType

#: Bounded, secret-free reason code for the typed validation error below.
INCONSISTENT_PRIVILEGE_CLAIMS_REASON = "inconsistent_privilege_claims"


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
