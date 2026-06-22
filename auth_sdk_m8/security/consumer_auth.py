"""Per-consumer credential verification primitives (Phase 9.1, near-term).

These primitives replace the single shared ``PRIVATE_API_SECRET`` — one secret
every consumer presents, rarely rotated, with a fleet-wide blast radius — with a
**map of consumer ids → hashed, scoped per-consumer secrets**. A caller presents
two headers, ``X-Internal-Client`` (who it is) and ``X-Internal-Token`` (its
secret); the issuer (``fa-auth-m8``) verifies the pair against the registry and
authorizes the requested private operation only if the matched credential
carries the required scope.

Why this lives in the SDK
-------------------------
``auth-sdk-m8`` is the only common dependency of both the issuer (``fa-auth-m8``)
and the consumer framework (``fastapi-m8``), so the *verification* building
blocks live here and every service reuses one implementation. Issuing/persisting
the credential map and the medium-term exchange of a bootstrap secret for a
short-TTL scoped service token are the **issuer's** concern (``fa-auth-m8``); the
SDK owns only the framework-agnostic verification logic.

Design notes
------------
- **Hashed at rest.** Secrets are stored as a salted SHA-256 digest
  (``sha256$<salt_hex>$<digest_hex>``), never in plaintext, so the registry can
  be loaded from a config/secret file without holding raw secrets in memory.
  Per-consumer secrets are high-entropy service credentials (not user passwords),
  so a salted single-round digest is the right cost/threat trade-off; the salt
  defeats cross-consumer hash equality and rainbow tables.
- **Deny by default.** A credential carries *no* scope unless one is explicitly
  granted — private operations are refused until a scope is added.
- **No client-enumeration oracle.** :meth:`ConsumerCredentialRegistry.verify`
  runs a constant-time digest comparison (against a throwaway credential when the
  client id is unknown) and reports unknown-client and wrong-secret identically,
  so a caller cannot probe which client ids exist by timing or error shape.

The FastAPI dependency that wires these into a route lives in
:mod:`auth_sdk_m8.security.guards` (``make_consumer_authorizer``), keeping this
module framework-agnostic.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum

#: Header naming the calling consumer, paired with ``X-Internal-Token``.
INTERNAL_CLIENT_HEADER = "X-Internal-Client"

_ALGORITHM = "sha256"
_ENCODING_SEPARATOR = "$"
_SALT_BYTES = 16


class ConsumerScope(StrEnum):
    """Well-known scopes a per-consumer credential may carry.

    These name the scopes the m8 trio recognises; operators may also grant
    arbitrary custom scope strings. Credentials hold *no* scope by default — a
    consumer is denied every private operation until explicitly granted one.
    """

    INTROSPECTION = "introspection"
    EVENT_STREAM = "event-stream"
    USER_CREATE = "user-create"


class ConsumerAuthError(Exception):
    """Base class for per-consumer authentication/authorization failures."""


class ConsumerAuthenticationError(ConsumerAuthError):
    """Unknown consumer id or wrong secret.

    Deliberately does **not** distinguish the two cases, so a caller cannot probe
    which client ids exist.
    """


class ConsumerScopeError(ConsumerAuthError):
    """Authenticated consumer lacks the scope required for the operation."""


def _hash_secret(secret: str, salt: bytes) -> str:
    """Return the hex SHA-256 digest of ``salt + secret``."""
    return hashlib.sha256(salt + secret.encode("utf-8")).hexdigest()


def _normalise_scopes(scopes: object) -> frozenset[str]:
    """Coerce a scope, or iterable of scopes, into a ``frozenset[str]``.

    A bare ``str``/:class:`ConsumerScope` is treated as a single scope (rather
    than an iterable of characters, which the footgun ``frozenset("abc")`` would
    produce).
    """
    if isinstance(scopes, str):
        return frozenset({str(scopes)})
    if not isinstance(scopes, Iterable):
        raise TypeError("scopes must be a string or an iterable of strings")
    return frozenset(str(scope) for scope in scopes)


@dataclass(frozen=True)
class ConsumerCredential:
    """One consumer's hashed bootstrap secret and the scopes it is granted."""

    client_id: str
    digest: str
    salt: str
    scopes: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def create(
        cls,
        client_id: str,
        secret: str,
        scopes: object = (),
        *,
        salt: bytes | None = None,
    ) -> ConsumerCredential:
        """Build a credential by hashing a plaintext *secret*.

        Args:
            client_id: Non-empty consumer identifier (the ``X-Internal-Client``
                value).
            secret: Non-empty plaintext bootstrap secret.
            scopes: A scope, or iterable of scopes, to grant (default: none).
            salt: Explicit salt bytes; a random 16-byte salt is generated when
                omitted. Pass this only to reproduce a known digest (tests).

        Returns:
            A frozen :class:`ConsumerCredential` holding the salted digest.
        """
        if not client_id:
            raise ValueError("client_id must be a non-empty string")
        if not secret:
            raise ValueError("secret must be a non-empty string")
        salt_bytes = salt if salt is not None else secrets.token_bytes(_SALT_BYTES)
        return cls(
            client_id=client_id,
            digest=_hash_secret(secret, salt_bytes),
            salt=salt_bytes.hex(),
            scopes=_normalise_scopes(scopes),
        )

    @classmethod
    def from_encoded(
        cls,
        client_id: str,
        encoded: str,
        scopes: object = (),
    ) -> ConsumerCredential:
        """Build a credential from a stored ``sha256$<salt>$<digest>`` string.

        This is the load path: the issuer persists :attr:`encoded_secret` and
        rebuilds the registry from those strings without ever holding the
        plaintext.
        """
        algorithm, _, rest = encoded.partition(_ENCODING_SEPARATOR)
        salt_hex, _, digest = rest.partition(_ENCODING_SEPARATOR)
        if algorithm != _ALGORITHM or not salt_hex or not digest:
            raise ValueError("encoded secret must be 'sha256$<salt_hex>$<digest_hex>'")
        try:
            bytes.fromhex(salt_hex)
            bytes.fromhex(digest)
        except ValueError as exc:
            raise ValueError("encoded secret salt/digest must be hex") from exc
        return cls(
            client_id=client_id,
            digest=digest,
            salt=salt_hex,
            scopes=_normalise_scopes(scopes),
        )

    @property
    def encoded_secret(self) -> str:
        """Return the portable ``sha256$<salt_hex>$<digest_hex>`` form."""
        sep = _ENCODING_SEPARATOR
        return f"{_ALGORITHM}{sep}{self.salt}{sep}{self.digest}"

    def verify_secret(self, provided: str | None) -> bool:
        """Constant-time check that *provided* hashes to this credential's digest.

        A missing/empty value never matches. The comparison runs in constant
        time via :func:`secrets.compare_digest`.
        """
        if not provided:
            return False
        candidate = _hash_secret(provided, bytes.fromhex(self.salt))
        return secrets.compare_digest(candidate, self.digest)

    def has_scope(self, scope: object) -> bool:
        """Return whether this credential was granted *scope*."""
        return str(scope) in self.scopes


def _build_credentials(
    mapping: Mapping[str, object],
    factory: object,
) -> list[ConsumerCredential]:
    """Build credentials from a ``client_id → material | (material, scopes)`` map."""
    credentials: list[ConsumerCredential] = []
    for client_id, value in mapping.items():
        if isinstance(value, tuple):
            material, scopes = value
        else:
            material, scopes = value, ()
        credentials.append(factory(client_id, material, scopes))  # type: ignore[operator]
    return credentials


class ConsumerCredentialRegistry:
    """A lookup of consumer id → :class:`ConsumerCredential` with safe verify."""

    def __init__(self, credentials: Iterable[ConsumerCredential] = ()) -> None:
        """Build a registry, rejecting duplicate client ids."""
        self._by_id: dict[str, ConsumerCredential] = {}
        for credential in credentials:
            self.register(credential)
        # Throwaway credential used to keep verify() timing uniform when the
        # client id is unknown (no client-enumeration oracle).
        self._dummy = ConsumerCredential.create("\x00dummy", secrets.token_hex(32))

    def register(self, credential: ConsumerCredential) -> ConsumerCredentialRegistry:
        """Add *credential*, raising on a duplicate client id."""
        if credential.client_id in self._by_id:
            raise ValueError(
                f"duplicate consumer credential for {credential.client_id!r}"
            )
        self._by_id[credential.client_id] = credential
        return self

    @classmethod
    def from_secrets(cls, mapping: Mapping[str, object]) -> ConsumerCredentialRegistry:
        """Build a registry by hashing plaintext secrets from a mapping.

        Each value is either the plaintext secret, or a ``(secret, scopes)``
        tuple. Convenience for tests/bootstrap; production loads hashed strings
        via :meth:`from_encoded`.
        """
        return cls(_build_credentials(mapping, ConsumerCredential.create))

    @classmethod
    def from_encoded(cls, mapping: Mapping[str, object]) -> ConsumerCredentialRegistry:
        """Build a registry from stored ``sha256$<salt>$<digest>`` strings.

        Each value is either the encoded string, or an ``(encoded, scopes)``
        tuple.
        """
        return cls(_build_credentials(mapping, ConsumerCredential.from_encoded))

    @property
    def client_ids(self) -> frozenset[str]:
        """Return the set of registered consumer ids."""
        return frozenset(self._by_id)

    def get(self, client_id: str) -> ConsumerCredential | None:
        """Return the credential for *client_id*, or ``None`` if unregistered."""
        return self._by_id.get(client_id)

    def verify(
        self, client_id: str | None, secret: str | None
    ) -> ConsumerCredential | None:
        """Authenticate a ``(client_id, secret)`` pair.

        Returns the matched credential, or ``None`` when the client id is unknown
        *or* the secret is wrong (the two are indistinguishable to the caller). A
        constant-time digest comparison runs in both branches so an unknown
        client id is not faster than a wrong secret.
        """
        credential = self._by_id.get(client_id) if client_id else None
        if credential is None:
            self._dummy.verify_secret(secret)
            return None
        if not credential.verify_secret(secret):
            return None
        return credential

    def authorize(
        self,
        client_id: str | None,
        secret: str | None,
        required_scope: object = None,
    ) -> ConsumerCredential:
        """Authenticate, then enforce *required_scope* if given.

        Args:
            client_id: The ``X-Internal-Client`` value.
            secret: The ``X-Internal-Token`` value.
            required_scope: Scope the operation needs, or ``None`` to require
                authentication only.

        Returns:
            The authenticated :class:`ConsumerCredential`.

        Raises:
            ConsumerAuthenticationError: Unknown client id or wrong secret.
            ConsumerScopeError: Authenticated but missing *required_scope*.
        """
        credential = self.verify(client_id, secret)
        if credential is None:
            raise ConsumerAuthenticationError("unknown consumer id or invalid secret")
        if required_scope is not None and not credential.has_scope(required_scope):
            raise ConsumerScopeError(
                f"consumer {credential.client_id!r} lacks scope {str(required_scope)!r}"
            )
        return credential
