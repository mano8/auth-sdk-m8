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

    Handles both MySQL and PostgreSQL error message formats.

    Returns:
        A list of dicts with keys ``table``, ``field_name``, and ``error``.
    """
    error_message = str(exc.orig)
    errors: list[dict] = []

    # MySQL: Duplicate entry 'val' for key 'table.field'
    for match in re.findall(
        r"Duplicate entry '(.+)' for key '([^'.]+)\.([^'.]+)'", error_message
    ):
        errors.append(
            {"table": match[1], "field_name": match[2], "error": "Duplicate entry already exists."}
        )

    # PostgreSQL: duplicate key value violates unique constraint
    for match in re.findall(
        r'duplicate key value violates unique constraint "[^"]+"\nDETAIL:.*?Key \(([^)]+)\)=\([^)]*\) already exists',
        error_message,
        re.DOTALL | re.IGNORECASE,
    ):
        errors.append({"table": None, "field_name": match, "error": "Duplicate entry already exists."})

    # MySQL: FOREIGN KEY (`field`) REFERENCES `table`
    for match in re.findall(
        r"FOREIGN KEY \(`(.+?)`\) REFERENCES `(.+?)`", error_message
    ):
        errors.append(
            {
                "table": match[1],
                "field_name": match[0],
                "error": f"Invalid foreign key reference in '{match[0]}'.",
            }
        )

    # PostgreSQL: foreign key constraint violation
    for match in re.findall(
        r'on table "[^"]+" violates foreign key constraint "[^"]+"\nDETAIL:.*?Key \(([^)]+)\)=\([^)]*\) is not present in table "([^"]+)"',
        error_message,
        re.DOTALL,
    ):
        errors.append(
            {
                "table": match[1],
                "field_name": match[0],
                "error": f"Invalid foreign key reference in '{match[0]}'.",
            }
        )

    # MySQL: Column 'field' cannot be null
    for match in re.findall(r"Column '(.+?)' cannot be null", error_message):
        errors.append({"table": None, "field_name": match, "error": f"Field '{match}' cannot be null."})

    # PostgreSQL: null value in column "field" of relation "table"
    for match in re.findall(
        r'null value in column "([^"]+)" of relation "([^"]+)" violates not-null constraint',
        error_message,
    ):
        errors.append(
            {"table": match[1], "field_name": match[0], "error": f"Field '{match[0]}' cannot be null."}
        )

    # MySQL: Field 'field' doesn't have a default value
    for match in re.findall(
        r"Field '(.+?)' doesn't have a default value", error_message
    ):
        errors.append({"table": None, "field_name": match, "error": f"Field '{match}' requires a value."})

    if not errors:
        errors.append({"table": None, "field_name": None, "error": "Unknown database integrity error"})

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
