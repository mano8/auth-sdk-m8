"""Custom exceptions for auth-sdk-m8."""


class InvalidToken(Exception):
    """Raised when a JWT token is invalid, expired, or of the wrong type."""


class ConfigurationError(RuntimeError):
    """Fatal application configuration error."""
