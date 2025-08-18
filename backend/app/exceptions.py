"""Custom exceptions and error handlers for the EASM application."""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import HTTPException, Request, status
from fastapi.responses import JSONResponse
import logging

logger = logging.getLogger(__name__)


class EASMException(Exception):
    """Base exception for all EASM-specific errors."""
    
    def __init__(
        self,
        message: str,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.details = details or {}


class ValidationException(EASMException):
    """Raised when input validation fails."""
    
    def __init__(self, message: str, field: Optional[str] = None):
        details = {"field": field} if field else {}
        super().__init__(message, status.HTTP_422_UNPROCESSABLE_ENTITY, details)


class ResourceNotFoundException(EASMException):
    """Raised when a requested resource is not found."""
    
    def __init__(self, resource_type: str, resource_id: str):
        message = f"{resource_type} with id '{resource_id}' not found"
        super().__init__(message, status.HTTP_404_NOT_FOUND, {"resource_type": resource_type, "resource_id": resource_id})


class ConflictException(EASMException):
    """Raised when an operation conflicts with existing state."""
    
    def __init__(self, message: str, conflict_type: Optional[str] = None):
        details = {"conflict_type": conflict_type} if conflict_type else {}
        super().__init__(message, status.HTTP_409_CONFLICT, details)


class RateLimitException(EASMException):
    """Raised when rate limit is exceeded."""
    
    def __init__(self, message: str = "Rate limit exceeded", retry_after: Optional[int] = None):
        details = {"retry_after": retry_after} if retry_after else {}
        super().__init__(message, status.HTTP_429_TOO_MANY_REQUESTS, details)


class ExternalServiceException(EASMException):
    """Raised when an external service call fails."""
    
    def __init__(self, service: str, message: str, original_error: Optional[Exception] = None):
        details = {"service": service}
        if original_error:
            details["original_error"] = str(original_error)
        super().__init__(message, status.HTTP_503_SERVICE_UNAVAILABLE, details)


class AuthenticationException(EASMException):
    """Raised when authentication fails."""
    
    def __init__(self, message: str = "Authentication required"):
        super().__init__(message, status.HTTP_401_UNAUTHORIZED)


class AuthorizationException(EASMException):
    """Raised when authorization fails."""
    
    def __init__(self, message: str = "Insufficient permissions"):
        super().__init__(message, status.HTTP_403_FORBIDDEN)


async def easm_exception_handler(request: Request, exc: EASMException) -> JSONResponse:
    """Handle EASM-specific exceptions."""
    logger.warning(
        "easm_exception",
        extra={
            "exception_type": type(exc).__name__,
            "message": exc.message,
            "status_code": exc.status_code,
            "details": exc.details,
            "path": request.url.path,
        }
    )
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "message": exc.message,
                "type": type(exc).__name__,
                "details": exc.details,
            }
        },
    )


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle unexpected exceptions."""
    logger.exception(
        "unhandled_exception",
        extra={
            "exception_type": type(exc).__name__,
            "path": request.url.path,
        }
    )
    
    # Don't expose internal errors in production
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "message": "An internal error occurred",
                "type": "InternalServerError",
            }
        },
    )


def register_exception_handlers(app):
    """Register all exception handlers with the FastAPI app."""
    app.add_exception_handler(EASMException, easm_exception_handler)
    app.add_exception_handler(Exception, generic_exception_handler)
