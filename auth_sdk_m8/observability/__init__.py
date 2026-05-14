"""Optional Prometheus observability for m8 services.

Install the extra to use:  pip install auth-sdk-m8[observability]

Usage in any FastAPI service::

    from auth_sdk_m8.observability.metrics import setup, get, render
    from auth_sdk_m8.observability.middleware import MetricsMiddleware
    from auth_sdk_m8.observability.settings import ObservabilitySettingsMixin
"""
