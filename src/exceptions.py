"""Structured error types returned to API clients."""

from __future__ import annotations


class SurakshaEdgeError(Exception):
    """Base application error with a machine-readable code."""

    def __init__(self, message: str, *, code: str = "internal_error", status_code: int = 500) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code


class ValidationFailed(SurakshaEdgeError):
    def __init__(self, message: str, *, code: str = "validation_error") -> None:
        super().__init__(message, code=code, status_code=400)


class NotFoundError(SurakshaEdgeError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="not_found", status_code=404)


class AuthError(SurakshaEdgeError):
    def __init__(self, message: str = "Authentication required") -> None:
        super().__init__(message, code="unauthorized", status_code=401)


class RateLimitError(SurakshaEdgeError):
    def __init__(self, message: str = "Rate limit exceeded") -> None:
        super().__init__(message, code="rate_limited", status_code=429)


class UnsafeInputError(SurakshaEdgeError):
    def __init__(self, message: str, *, code: str = "unsafe_input") -> None:
        super().__init__(message, code=code, status_code=400)
