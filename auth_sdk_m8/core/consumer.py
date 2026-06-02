"""ConsumerAuthMixin — auth fields for consumer microservices.

Add to any ``Settings`` that inherits from ``CommonSettings`` to gain
``INTROSPECTION_URL``, ``PRIVATE_API_SECRET``, and the validator that
enforces their presence for stateful consumers.

Example::

    class MySettings(ConsumerAuthMixin, CommonSettings):
        ...
"""

from typing import Optional

from pydantic import BaseModel, HttpUrl, SecretStr, model_validator


class ConsumerAuthMixin(BaseModel):
    """Consumer-side auth config mixin.

    Must be combined with ``CommonSettings`` (relies on inherited
    ``AUTH_SERVICE_ROLE`` and ``is_stateful``).
    """

    INTROSPECTION_URL: Optional[HttpUrl] = None
    PRIVATE_API_SECRET: Optional[SecretStr] = None

    @model_validator(mode="after")
    def _require_introspection_for_stateful_consumer(self) -> "ConsumerAuthMixin":
        """Raise if a stateful consumer is missing revocation config."""
        role = getattr(self, "AUTH_SERVICE_ROLE", None)
        stateful = getattr(self, "is_stateful", False)
        if role == "consumer" and stateful:
            missing: list[str] = []
            if self.INTROSPECTION_URL is None:
                missing.append("INTROSPECTION_URL")
            if self.PRIVATE_API_SECRET is None:
                missing.append("PRIVATE_API_SECRET")
            if missing:
                raise ValueError("Stateful consumer requires " + " and ".join(missing))
        return self
