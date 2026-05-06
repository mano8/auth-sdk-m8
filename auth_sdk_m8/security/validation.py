"""Validation models for JWT decoding."""

from typing import Sequence

from pydantic import BaseModel, Field, model_validator


class TokenValidationConfig(BaseModel):
    """
    Configuration for JWT validation behavior.

    Defaults are permissive for backward compatibility.
    """

    issuer: str | None = None
    audience: Sequence[str] | str | None = None

    require_iss: bool = False
    require_aud: bool = False

    required_claims: list[str] = Field(
        default_factory=lambda: ["exp", "sub", "jti", "type"]
    )
    allowed_algorithms: list[str] = Field(default_factory=lambda: ["HS256"])
    leeway_seconds: int = 5

    @model_validator(mode="after")
    def validate_dependencies(self) -> "TokenValidationConfig":
        """Ensure strict validation flags have the config they need."""
        if self.require_iss and not self.issuer:
            raise ValueError("issuer must be provided when require_iss=True")
        if self.require_aud and not self.audience:
            raise ValueError("audience must be provided when require_aud=True")
        if not self.allowed_algorithms:
            raise ValueError("allowed_algorithms must not be empty")
        return self

    @classmethod
    def strict(
        cls,
        issuer: str,
        audience: Sequence[str] | str,
    ) -> "TokenValidationConfig":
        """Return a stricter validation profile for new integrations."""
        return cls(
            issuer=issuer,
            audience=audience,
            require_iss=True,
            require_aud=True,
            required_claims=["exp", "sub", "jti", "type", "iat", "nbf"],
            allowed_algorithms=["HS256"],
            leeway_seconds=2,
        )
