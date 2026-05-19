"""JWT validation, token hashing and PKCE helpers.

Requires the `security` extra:  pip install "auth-sdk-m8[security]"
FastAPI cookie helpers additionally require:  pip install "auth-sdk-m8[fastapi]"
"""

import base64
import hashlib
import json
import logging
import uuid
import warnings
from datetime import datetime, timezone
from os import urandom
from typing import Any, Optional, Tuple, Union

import jwt
from jwt import ExpiredSignatureError, PyJWTError

from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.auth import TokenDecodeProps, TokenSecret, TokenUserData

# Import from submodules directly to avoid circular imports with security/__init__.py
from auth_sdk_m8.security.token_validator import TokenValidator
from auth_sdk_m8.security.validation import TokenValidationConfig

logger = logging.getLogger(__name__)

LEGACY_ACCESS_TOKEN_VALIDATION_CONFIG = TokenValidationConfig(
    required_claims=["exp"],
    leeway_seconds=0,
)

# Algorithms accepted for refresh-token signing (defense-in-depth whitelist).
_ALLOWED_REFRESH_ALGORITHMS: frozenset[str] = frozenset({"HS256", "RS256", "ES256"})

_REFRESH_DECODE_OPTIONS: dict[str, Any] = {"require": ["exp", "sub", "jti", "type"]}


def _decode_refresh_payload(
    token: str,
    secrets: TokenSecret,
    old_secrets: Optional[TokenSecret],
) -> dict[str, Any]:
    """Decode a refresh JWT and return the raw payload.

    Tries *secrets* first. On a signature failure (not expiry), retries with
    *old_secrets* when provided — supports zero-downtime key rotation.
    Logs a WARNING when the old key is accepted.
    """
    try:
        return jwt.decode(
            token,
            secrets.secret_key.get_secret_value(),
            algorithms=[secrets.algorithm],
            options=_REFRESH_DECODE_OPTIONS,
        )
    except ExpiredSignatureError as ex:
        raise InvalidToken("Refresh token expired") from ex
    except PyJWTError:
        pass

    if old_secrets is None:
        raise InvalidToken("Invalid refresh token")

    try:
        payload = jwt.decode(
            token,
            old_secrets.secret_key.get_secret_value(),
            algorithms=[old_secrets.algorithm],
            options=_REFRESH_DECODE_OPTIONS,
        )
        logger.warning(
            "Refresh token accepted with REFRESH_SECRET_KEY_OLD — "
            "remove old key once all old-key tokens have expired"
        )
        return payload
    except ExpiredSignatureError as ex:
        raise InvalidToken("Refresh token expired") from ex
    except PyJWTError as ex:
        raise InvalidToken("Invalid refresh token") from ex


class ComSecurityHelper:
    """Shared JWT and cryptographic utilities.

    All methods are static — instantiation is not required.
    """

    @staticmethod
    def decode_access_token(token_data: TokenDecodeProps) -> TokenUserData:
        """Decode and validate a JWT access token.

        Args:
            token_data: Token string, signing secret, and algorithm.

        Returns:
            Parsed token payload as ``TokenUserData``.

        Raises:
            InvalidToken: If the token is expired, invalid, or not an access token.

        .. deprecated::
            Use ``TokenValidator`` instead.
        """
        warnings.warn(
            "decode_access_token is deprecated; use TokenValidator",
            DeprecationWarning,
            stacklevel=2,
        )
        validator = TokenValidator(
            secrets=TokenSecret(
                secret_key=token_data.secret_key,
                algorithm=token_data.algorithm,
            ),
            config=LEGACY_ACCESS_TOKEN_VALIDATION_CONFIG,
        )
        return validator.validate_access_token(token_data.access_token)

    @staticmethod
    def decode_refresh_token(
        token: str,
        secrets: TokenSecret,
        return_jti: bool = False,
        old_secrets: Optional[TokenSecret] = None,
    ) -> Union[uuid.UUID, Tuple[uuid.UUID, str]]:
        """Decode and validate a JWT refresh token.

        Args:
            token: Encoded refresh token string.
            secrets: Current signing key and algorithm.
            return_jti: When True, returns ``(user_id, jti)`` instead of just
                ``user_id``.
            old_secrets: Previous signing key used during key rotation. When
                provided and the current key fails with a signature error (not
                expiry), the token is retried against this key. Expired tokens
                are never retried — expiry is independent of the signing key.

        Returns:
            ``user_id`` UUID, or ``(user_id, jti)`` when *return_jti* is True.

        Raises:
            InvalidToken: If the token is invalid or not a refresh token.
        """
        if secrets.algorithm not in _ALLOWED_REFRESH_ALGORITHMS:
            raise InvalidToken("Unsupported signing algorithm for refresh token")

        payload = _decode_refresh_payload(token, secrets, old_secrets)

        if payload.get("type") != "refresh":
            raise InvalidToken("Not a refresh token")

        exp = payload.get("exp")
        if exp is None or exp < datetime.now(timezone.utc).timestamp():
            raise InvalidToken("Refresh token expired")

        try:
            user_id = uuid.UUID(payload["sub"])
        except (ValueError, AttributeError) as ex:
            raise InvalidToken("Invalid refresh token") from ex

        jti = payload.get("jti")
        if not isinstance(jti, str) or not jti:
            raise InvalidToken("Invalid refresh token")

        if return_jti:
            return user_id, jti  # type: ignore[return-value]
        return user_id

    @staticmethod
    def get_refresh_token_from_cookie(refresh_token: str = None) -> str:
        """Extract the refresh token from an HTTP-only cookie.

        Intended for use as a FastAPI dependency.
        Import ``fastapi.Cookie`` at call-site to enable cookie injection::

            from fastapi import Cookie, Depends
            from auth_sdk_m8.core.security import ComSecurityHelper

            def my_dep(t: str = Cookie(None, alias="refresh_token")):
                return ComSecurityHelper.get_refresh_token_from_cookie(t)

        Raises:
            HTTPException 401: If the cookie is absent.
        """
        from fastapi import HTTPException  # noqa: PLC0415

        if not refresh_token:
            raise HTTPException(status_code=401, detail="Refresh token missing")
        return refresh_token

    @staticmethod
    def get_access_token_from_cookie(access_token: str = None) -> str:
        """Extract the access token from an HTTP-only cookie.

        See ``get_refresh_token_from_cookie`` for usage pattern.

        Raises:
            HTTPException 401: If the cookie is absent.
        """
        from fastapi import HTTPException  # noqa: PLC0415

        if not access_token:
            raise HTTPException(status_code=401, detail="Access token missing")
        return access_token

    @staticmethod
    def hash_token(token: str) -> str:
        """Return a SHA-256 hex digest of *token* for safe storage."""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def create_state(pkce: str) -> str:
        """Create a base64-encoded OAuth2 state parameter embedding the PKCE verifier.

        Args:
            pkce: PKCE code verifier string.

        Returns:
            Base64-encoded JSON state string.
        """
        raw = json.dumps({"pkce": pkce}).encode("utf-8")
        return base64.b64encode(raw).decode("utf-8")

    @staticmethod
    def create_pkce() -> str:
        """Generate a PKCE code verifier (43–128 URL-safe characters).

        Returns:
            URL-safe base64 string without padding.
        """
        return base64.urlsafe_b64encode(urandom(32)).decode("utf-8").rstrip("=")
