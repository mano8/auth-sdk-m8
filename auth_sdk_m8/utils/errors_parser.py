"""
Database and validation error parsers.

Requires the `db` extra:  pip install "auth-sdk-m8[db]"
"""
import re

from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError


def parse_integrity_error(exc: IntegrityError) -> list[dict]:
    """
    Parse an SQLAlchemy ``IntegrityError`` into structured error details.

    Returns:
        A list of dicts with keys ``table``, ``field_name``, and ``error``.
    """
    error_message = str(exc.orig)
    errors: list[dict] = []

    unique_matches = re.findall(
        r"Duplicate entry '(.+)' for key '([^'.]+)\.([^'.]+)'", error_message
    )
    for match in unique_matches:
        errors.append(
            {
                "table": match[1],
                "field_name": match[2],
                "error": f"Duplicate entry: '{match[0]}' already exists.",
            }
        )

    fk_matches = re.findall(
        r"FOREIGN KEY \(`(.+?)`\) REFERENCES `(.+?)`", error_message
    )
    for match in fk_matches:
        errors.append(
            {
                "table": match[1],
                "field_name": match[0],
                "error": f"Invalid foreign key reference in '{match[0]}'.",
            }
        )

    not_null_matches = re.findall(r"Column '(.+?)' cannot be null", error_message)
    for match in not_null_matches:
        errors.append(
            {
                "table": None,
                "field_name": match,
                "error": f"Field '{match}' cannot be null.",
            }
        )

    default_matches = re.findall(
        r"Field '(.+?)' doesn't have a default value", error_message
    )
    for match in default_matches:
        errors.append(
            {
                "table": None,
                "field_name": match,
                "error": f"Field '{match}' requires a value.",
            }
        )

    if not errors:
        errors.append(
            {
                "table": None,
                "field_name": None,
                "error": "Unknown database integrity error",
            }
        )

    return errors


def parse_pydantic_errors(exc: ValidationError) -> list[dict]:
    """
    Parse a Pydantic ``ValidationError`` into structured error details.

    Returns:
        A list of dicts with keys ``field_name`` and ``error``.
    """
    errors: list[dict] = []
    for error in exc.errors():
        field = ".".join(str(loc) for loc in error.get("loc", []))
        message = error.get("msg", "Validation error")
        errors.append({"field_name": field, "error": message})
    return errors
