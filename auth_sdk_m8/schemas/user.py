"""User and session Pydantic schemas."""
import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field

from auth_sdk_m8.schemas.base import AuthProviderType, RoleType


class UserModel(BaseModel):
    """Pydantic representation of an authenticated user."""

    id: uuid.UUID
    email: EmailStr
    full_name: Optional[str] = None
    avatar: Optional[str] = None
    is_active: bool = True
    email_verified: bool = False
    is_superuser: bool = False
    role: RoleType = RoleType.USER


class SessionModel(BaseModel):
    """Pydantic representation of a client session."""

    id: uuid.UUID
    provider: AuthProviderType
    jwt_jti: str = Field(min_length=16, max_length=128, description="JWT ID")
    refresh_token_hash: str = Field(
        min_length=64, max_length=128, description="Hash of refresh token"
    )
    jwt_expires_at: datetime = Field(description="JWT expiration (UTC)")
    refresh_expires_at: datetime = Field(
        description="Refresh token expiration (UTC)"
    )
    external_access_token: Optional[str] = Field(
        default=None, max_length=2048, description="Google OAuth access token"
    )
    external_refresh_token: Optional[str] = Field(
        default=None, max_length=2048, description="Google OAuth refresh token"
    )
    external_token_expires_at: Optional[datetime] = Field(
        default=None, description="Google OAuth token expiration (UTC)"
    )
