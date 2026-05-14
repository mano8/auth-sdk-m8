"""BaseController — unified exception handling for FastAPI + SQLModel services.

Requires the `fastapi` and `db` extras:
    pip install "auth-sdk-m8[fastapi,db]"
"""

from typing import Union

from fastapi import HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy.exc import IntegrityError
from sqlmodel import Session

from auth_sdk_m8.schemas.base import ResponseError, ResponseErrorBase
from auth_sdk_m8.utils.errors_parser import parse_integrity_error, parse_pydantic_errors


class BaseController:
    """Mixin that provides standard error responses for FastAPI route handlers.

    Usage::

        from auth_sdk_m8.controllers.base import BaseController

        router = APIRouter()

        @router.get("/items", responses=BaseController.get_error_responses())
        def list_items(session: Session) -> Any:
            try:
                ...
            except Exception as ex:
                return BaseController.handle_exception(ex, session)
    """

    @staticmethod
    def get_error_responses() -> dict:
        """Return the standard 500-error response schema for ``responses=``."""
        return {500: {"model": ResponseErrorBase}}

    @staticmethod
    def _build_content(ex: Exception) -> ResponseErrorBase:
        if isinstance(ex, IntegrityError):
            return ResponseErrorBase(
                success=False,
                msg="Database integrity error: Possibly duplicate entry or invalid reference.",
                status_code=status.HTTP_400_BAD_REQUEST,
                from_error="IntegrityError",
                errors=parse_integrity_error(ex),
            )
        if isinstance(ex, ValidationError):
            return ResponseErrorBase(
                success=False,
                msg="Validation error.",
                from_error="ValidationError",
                status_code=status.HTTP_400_BAD_REQUEST,
                errors=parse_pydantic_errors(ex),
            )
        if isinstance(ex, (ValueError, TypeError, IOError)):
            return ResponseErrorBase(
                success=False,
                msg="Internal error.",
                from_error="InternalError",
                errors=[ResponseError(error=str(ex))],
                status_code=status.HTTP_400_BAD_REQUEST,
            )
        return ResponseErrorBase(
            success=False,
            msg="An unexpected error occurred.",
            from_error="Exception",
            errors=[ResponseError(error=str(ex))],
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    @staticmethod
    def handle_exception(
        ex: Exception,
        session: Union[Session, None] = None,
    ) -> JSONResponse:
        """Map a caught exception to a structured JSON error response.

        Always rolls back *session* if provided.  ``HTTPException`` is
        re-raised so FastAPI can handle it with its own status code.

        Args:
            ex: The caught exception.
            session: Optional SQLModel session to roll back.

        Returns:
            A ``JSONResponse`` with a ``ResponseErrorBase`` body.
        """
        if isinstance(ex, HTTPException):
            raise ex
        content = BaseController._build_content(ex)
        if session:
            session.rollback()
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=content.model_dump(),
        )
