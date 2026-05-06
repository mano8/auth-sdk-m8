"""Observability hooks for token validation events."""

from typing import Protocol


class ValidationHooks(Protocol):
    """Observer interface for token validation outcomes.

    Implement this protocol to plug structured logging, metrics, or tracing
    into ``TokenValidator``, ``TokenPolicy``, and ``RefreshTokenPolicy``.
    Every method receives only non-sensitive identifiers — never raw token
    strings or signing secrets.
    """

    def on_success(self, *, jti: str, sub: str, token_type: str) -> None:
        """Called after a token passes all validation checks.

        Args:
            jti: The JWT ID of the validated token.
            sub: The subject (user id) from the token payload.
            token_type: ``"access"`` or ``"refresh"``.
        """

    def on_failure(self, *, reason: str, token_type: str) -> None:
        """Called when a token fails any validation check.

        Args:
            reason: Short machine-readable label:
                ``"expired"``, ``"invalid"``, ``"wrong_type"``,
                ``"invalid_payload"``, ``"revoked"``, ``"reused"``.
            token_type: ``"access"`` or ``"refresh"``.
        """
