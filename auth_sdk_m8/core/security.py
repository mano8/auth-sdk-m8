"""
JWT validation, token hashing and PKCE helpers.

Requires the `security` extra:  pip install "auth-sdk-m8[security]"
FastAPI cookie helpers additionally require:  pip install "auth-sdk-m8[fastapi]"
"""
import base64
import hashlib
import json
from datetime import datetime, timezone
from os import urandom
from typing import Tuple, Union
import uuid

import jwt
from jwt import PyJWTError, InvalidTokenError

from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.auth import TokenDecodeProps, TokenSecret, TokenUserData


class ComSecurityHelper:
    """
    Shared JWT and cryptographic utilities.

    All methods are static — instantiation is not required.
    """

    @staticmethod
    def decode_access_token(token_data: TokenDecodeProps) -> TokenUserData:
        """
        Decode and validate a JWT access token.

        Args:
            token_data: Token string, signing secret, and algorithm.

        Returns:
            Parsed token payload as ``TokenUserData``.

        Raises:
            InvalidToken: If the token is expired, invalid, or not an access token.
        """
        try:
            payload = jwt.decode(
                token_data.access_token,
                token_data.secret_key.get_secret_value(),
                algorithms=[token_data.algorithm],
            )
            if payload.get("type") != "access":
                raise InvalidToken("Not an access token")
            if payload.get("exp") < datetime.now(timezone.utc).timestamp():
                raise InvalidToken("Access token expired")
            return TokenUserData(**payload)
        except PyJWTError as ex:
            raise InvalidToken("Invalid access token") from ex

    @staticmethod
    def decode_refresh_token(
        token: str,
        secrets: TokenSecret,
        return_jti: bool = False,
    ) -> Union[uuid.UUID, Tuple[uuid.UUID, str]]:
        """
        Decode and validate a JWT refresh token.

        Args:
            token: Encoded refresh token string.
            secrets: Signing key and algorithm.
            return_jti: When True, returns ``(user_id, jti)`` instead of just ``user_id``.

        Returns:
            ``user_id`` UUID, or ``(user_id, jti)`` when *return_jti* is True.

        Raises:
            InvalidToken: If the token is invalid or not a refresh token.
        """
        try:
            payload = jwt.decode(
                token,
                secrets.secret_key.get_secret_value(),
                algorithms=[secrets.algorithm],
            )
            if payload.get("type") != "refresh":
                raise InvalidToken("Not a refresh token")
            user_id = uuid.UUID(payload.get("sub"))
            jti = payload.get("jti")
            if return_jti:
                return user_id, jti  # type: ignore[return-value]
            return user_id
        except PyJWTError as ex:
            raise InvalidToken("Invalid refresh token") from ex

    @staticmethod
    def get_refresh_token_from_cookie(refresh_token: str = None) -> str:
        """
        Extract the refresh token from an HTTP-only cookie.

        Intended for use as a FastAPI dependency.
        Import ``fastapi.Cookie`` at call-site to enable cookie injection:

            from fastapi import Cookie, Depends
            from auth_sdk_m8.core.security import ComSecurityHelper

            def my_dep(t: str = Cookie(None, alias="refresh_token")):
                return ComSecurityHelper.get_refresh_token_from_cookie(t)

        Raises:
            HTTPException 401: If the cookie is absent.
        """
        # Import here to keep fastapi optional at module level.
        from fastapi import HTTPException  # noqa: PLC0415

        if not refresh_token:
            raise HTTPException(status_code=401, detail="Refresh token missing")
        return refresh_token

    @staticmethod
    def get_access_token_from_cookie(access_token: str = None) -> str:
        """
        Extract the access token from an HTTP-only cookie.

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
        """
        Create a base64-encoded OAuth2 state parameter embedding the PKCE verifier.

        Args:
            pkce: PKCE code verifier string.

        Returns:
            Base64-encoded JSON state string.
        """
        raw = json.dumps({"pkce": pkce}).encode("utf-8")
        return base64.b64encode(raw).decode("utf-8")

    @staticmethod
    def create_pkce() -> str:
        """
        Generate a PKCE code verifier (43–128 URL-safe characters).

        Returns:
            URL-safe base64 string without padding.
        """
        return base64.urlsafe_b64encode(urandom(32)).decode("utf-8").rstrip("=")
