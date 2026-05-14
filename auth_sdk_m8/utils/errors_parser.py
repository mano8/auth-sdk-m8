"""Database and validation error parsers.

Requires the `db` extra:  pip install "auth-sdk-m8[db]"
"""

import re

from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError

from auth_sdk_m8.schemas.base import ResponseError


def _parse_mysql_errors(message: str) -> list[ResponseError]:
    errors: list[ResponseError] = []
    for match in re.findall(
        r"Duplicate entry '(.+)' for key '([^'.]+)\.([^'.]+)'", message
    ):
        errors.append(
            ResponseError(
                table=match[1],
                field_name=match[2],
                error="Duplicate entry already exists.",
            )
        )
    for match in re.findall(r"FOREIGN KEY \(`(.+?)`\) REFERENCES `(.+?)`", message):
        errors.append(
            ResponseError(
                table=match[1],
                field_name=match[0],
                error=f"Invalid foreign key reference in '{match[0]}'.",
            )
        )
    for match in re.findall(r"Column '(.+?)' cannot be null", message):
        errors.append(
            ResponseError(
                table=None, field_name=match, error=f"Field '{match}' cannot be null."
            )
        )
    for match in re.findall(r"Field '(.+?)' doesn't have a default value", message):
        errors.append(
            ResponseError(
                table=None, field_name=match, error=f"Field '{match}' requires a value."
            )
        )
    return errors


def _parse_postgres_errors(message: str) -> list[ResponseError]:
    errors: list[ResponseError] = []
    for match in re.findall(
        r'duplicate key value violates unique constraint "[^"]+"\nDETAIL:.*?Key \(([^)]+)\)=\([^)]*\) already exists',
        message,
        re.DOTALL | re.IGNORECASE,
    ):
        errors.append(
            ResponseError(
                table=None, field_name=match, error="Duplicate entry already exists."
            )
        )
    for match in re.findall(
        r'on table "[^"]+" violates foreign key constraint "[^"]+"\nDETAIL:.*?Key \(([^)]+)\)=\([^)]*\) is not present in table "([^"]+)"',
        message,
        re.DOTALL,
    ):
        errors.append(
            ResponseError(
                table=match[1],
                field_name=match[0],
                error=f"Invalid foreign key reference in '{match[0]}'.",
            )
        )
    for match in re.findall(
        r'null value in column "([^"]+)" of relation "([^"]+)" violates not-null constraint',
        message,
    ):
        errors.append(
            ResponseError(
                table=match[1],
                field_name=match[0],
                error=f"Field '{match[0]}' cannot be null.",
            )
        )
    return errors


def parse_integrity_error(exc: IntegrityError) -> list[ResponseError]:
    """Parse an SQLAlchemy ``IntegrityError`` into structured error details.

    Handles both MySQL and PostgreSQL error message formats.

    Returns:
        A list of ``ResponseError`` with ``table``, ``field_name``, and ``error``.
    """
    message = str(exc.orig)
    errors = _parse_mysql_errors(message) + _parse_postgres_errors(message)
    if not errors:
        errors.append(
            ResponseError(
                table=None, field_name=None, error="Unknown database integrity error"
            )
        )
    return errors


def parse_pydantic_errors(exc: ValidationError) -> list[ResponseError]:
    """Parse a Pydantic ``ValidationError`` into structured error details.

    Returns:
        A list of ``ResponseError`` with ``field_name`` and ``error``.
    """
    errors: list[ResponseError] = []
    for error in exc.errors():
        field = ".".join(str(loc) for loc in error.get("loc", []))
        message = error.get("msg", "Validation error")
        errors.append(ResponseError(field_name=field, error=message))
    return errors
