"""Pydantic-settings mixin that adds METRICS_ENABLED and METRICS_GROUPS fields."""

from pydantic import BaseModel


class ObservabilitySettingsMixin(BaseModel):
    """Add to any pydantic-settings Settings class to enable metrics config.

    Example::

        class Settings(ObservabilitySettingsMixin, CommonSettings):
            ...

    Environment variables:

    * ``METRICS_ENABLED`` — master switch (default: ``false``)
    * ``METRICS_GROUPS``  — comma-separated groups (default: ``"all"``)

    Valid group names: ``all``, ``traffic``, ``performance``,
    ``reliability``, ``health``, ``auth``.
    """

    # Observability — Prometheus metrics (disabled by default for zero overhead)
    METRICS_ENABLED: bool = False
    # Comma-separated groups to enable. Valid values:
    #   all, traffic, performance, reliability, health, auth
    # Examples: "all"  |  "traffic,performance"  |  "auth,health"
    METRICS_GROUPS: str = "all"
