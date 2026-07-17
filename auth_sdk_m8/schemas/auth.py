"""JWT token schemas shared across m8 microservices."""

from typing import Literal, Optional, Self

from pydantic import BaseModel, EmailStr, SecretStr, model_validator

from auth_sdk_m8.authorization import validate_privilege_claims
from auth_sdk_m8.schemas.base import RoleType
from auth_sdk_m8.schemas.shared import ValidationConstants

TokenType = Literal["access", "refresh"]
TokenAlgorithm = Literal["HS256", "RS256", "ES256"]

# Algorithms that use public/private key pairs instead of a shared secret.
# Secret-strength regex validation is skipped for these.
ASYMMETRIC_ALGORITHMS: frozenset[str] = frozenset({"RS256", "ES256"})


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
        """Enforce minimum strength on symmetric signing keys.

        Asymmetric algorithms (RS256, ES256) accept PEM-encoded keys and
        therefore bypass the symmetric-secret strength regex.
        """
        if self.algorithm in ASYMMETRIC_ALGORITHMS:
            return self
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
    """User fields embedded in the access token payload.

    ``role`` and ``is_superuser`` must agree per the canonical truth table
    (see :mod:`auth_sdk_m8.authorization`). Because ``TokenAccessData`` and
    ``TokenUserData`` both inherit this model, token creation and token
    consumption reject the same inconsistent pair.
    """

    email: EmailStr
    full_name: Optional[str] = None
    avatar: Optional[str] = None
    is_active: bool = True
    email_verified: bool = False
    is_superuser: bool = False
    role: RoleType = RoleType.USER
    # UUID as string; JWT payload must be JSON-serialisable
    tenant_id: Optional[str] = None

    @model_validator(mode="after")
    def validate_privilege_claim_consistency(self) -> Self:
        """Reject a ``role``/``is_superuser`` pair outside the truth table.

        Raises:
            InconsistentPrivilegeClaimsError: Wrapped by Pydantic into a
                ``ValidationError`` carrying only the bounded reason code.
        """
        validate_privilege_claims(self.role, self.is_superuser)
        return self


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
