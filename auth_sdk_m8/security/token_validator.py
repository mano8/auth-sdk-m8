"""Pure JWT validation helpers."""

from typing import Any

import jwt
from jwt import ExpiredSignatureError, PyJWTError
from pydantic import ValidationError

from auth_sdk_m8.core.exceptions import InvalidToken
from auth_sdk_m8.schemas.auth import TokenSecret, TokenUserData
from auth_sdk_m8.security.validation import TokenValidationConfig


class TokenValidator:
    """
    Pure access-token validator with no I/O or storage dependencies.

    This validator is intentionally synchronous. Stateful or network-backed
    checks belong in a separate policy layer.
    """

    def __init__(
        self,
        secrets: TokenSecret,
        config: TokenValidationConfig,
    ) -> None:
        self._secret = secrets.secret_key.get_secret_value()
        self._config = config

        if secrets.algorithm not in self._config.allowed_algorithms:
            raise ValueError(
                f"Algorithm '{secrets.algorithm}' not allowed by configuration"
            )

    def validate_access_token(self, token: str) -> TokenUserData:
        """Decode and validate an access token."""
        decode_kwargs: dict[str, Any] = {
            "key": self._secret,
            "algorithms": self._config.allowed_algorithms,
            "options": {
                "require": self._config.required_claims,
                "verify_aud": self._config.require_aud,
                "verify_iss": self._config.require_iss,
            },
            "leeway": self._config.leeway_seconds,
        }

        if self._config.require_aud:
            decode_kwargs["audience"] = self._config.audience

        if self._config.require_iss:
            decode_kwargs["issuer"] = self._config.issuer

        try:
            payload = jwt.decode(token, **decode_kwargs)
        except ExpiredSignatureError as ex:
            raise InvalidToken("Access token expired") from ex
        except PyJWTError as ex:
            raise InvalidToken("Invalid access token") from ex

        if payload.get("type") != "access":
            raise InvalidToken("Not an access token")

        try:
            return TokenUserData(**payload)
        except ValidationError as ex:
            raise InvalidToken("Invalid access token") from ex
