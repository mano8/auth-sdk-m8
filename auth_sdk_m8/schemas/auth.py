"""JWT token schemas shared across m8 microservices."""
from typing import Literal, Optional

from pydantic import BaseModel, EmailStr, SecretStr, model_validator

from auth_sdk_m8.schemas.base import RoleType
from auth_sdk_m8.schemas.shared import ValidationConstants

TokenType = Literal["access", "refresh"]
TokenAlgorithm = Literal["HS256", "RS256"]


class Token(BaseModel):
    """JWT access token response body."""

    access_token: str
    token_type: str = "bearer"


class TokenDecodeProps(BaseModel):
    """Parameters required to decode an access token."""

    access_token: str
    secret_key: SecretStr
    algorithm: TokenAlgorithm


class TokenSecret(BaseModel):
    """Signing key + algorithm pair used to create or verify tokens."""

    secret_key: SecretStr
    algorithm: TokenAlgorithm

    @model_validator(mode="after")
    def validate_secret_key(self) -> "TokenSecret":
        """Enforce minimum strength on the signing key."""
        if not ValidationConstants.SECRET_KEY_REGEX.match(
            self.secret_key.get_secret_value()
        ):
            raise ValueError("Invalid secret key format.")
        return self


class ExternalTokensData(BaseModel):
    """Google OAuth token data stored alongside the internal session."""

    expires: int
    access: SecretStr
    refresh: SecretStr


class TokenSubData(BaseModel):
    """Minimal token payload — subject only."""

    sub: str


class UserPayloadData(BaseModel):
    """User fields embedded in the access token payload."""

    email: EmailStr
    full_name: Optional[str] = None
    avatar: Optional[str] = None
    is_active: bool = True
    email_verified: bool = False
    is_superuser: bool = False
    role: RoleType = RoleType.USER


class TokenMinimalData(TokenSubData):
    """Token payload with subject and type."""

    type: Literal["access", "refresh"] = "access"


class TokenAccessData(TokenMinimalData, UserPayloadData):
    """Full payload used when creating an access token."""


class TokenUserData(TokenMinimalData, UserPayloadData):
    """Decoded access token payload (includes JTI and expiry)."""

    jti: str
    exp: Optional[int] = None


class TokenPayload(TokenSubData, UserPayloadData):
    """Generic token payload for backward compatibility."""
