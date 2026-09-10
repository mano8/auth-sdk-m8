"""Key resolution interfaces for token validation."""

from typing import Optional, Protocol, runtime_checkable

from auth_sdk_m8.schemas.auth import TokenSecret


class KeyResolver(Protocol):
    """Resolve a signing key for a token based on its optional ``kid`` header."""

    def resolve(self, kid: str | None) -> TokenSecret:
        """Return the key material and algorithm for the requested key id."""


@runtime_checkable
class RefreshableKeyResolver(KeyResolver, Protocol):
    """A ``KeyResolver`` that can re-fetch key material for a known ``kid``.

    Implemented by resolvers backed by a remote key set.  ``TokenValidator``
    calls ``refresh`` only after a signature failure on a ``kid`` the resolver
    already served — the signal that the key behind an unchanged identifier was
    replaced.  Implementations must throttle the underlying fetch themselves;
    the caller cannot, because the trigger is attacker-supplied.
    """

    def refresh(self, kid: str | None) -> Optional[TokenSecret]:
        """Re-fetch and return the current key for *kid*.

        Returns ``None`` when no fetch happened (throttled) or *kid* is absent
        from the refreshed key set.
        """
