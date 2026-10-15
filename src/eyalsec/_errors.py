"""Exceptions raised by the client.

Every exception the client raises on purpose is an :class:`EyalSecError`. An
answer with an error status becomes an :class:`APIError` subclass chosen by
the status code, so a script can catch exactly the case it handles::

    try:
        client.get_event(90210)
    except eyalsec.NotFoundError:
        ...  # not yours, or does not exist: the API answers both the same way
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Type

__all__ = [
    "EyalSecError",
    "ConfigurationError",
    "APIConnectionError",
    "APITimeoutError",
    "APIError",
    "BadRequestError",
    "AuthenticationError",
    "PermissionDeniedError",
    "NotFoundError",
    "ConflictError",
    "UnprocessableEntityError",
    "RateLimitError",
    "InternalServerError",
    "UnexpectedResponseError",
]


class EyalSecError(Exception):
    """Base class for every error this library raises on purpose."""


class ConfigurationError(EyalSecError):
    """The client cannot make a request as configured, for example no API key
    was given, or the address is plain ``http://`` to another machine."""


class APIConnectionError(EyalSecError):
    """The request did not get an answer: DNS, TLS, a refused connection or a
    dropped one. Nothing is known about whether a write was applied."""


class APITimeoutError(APIConnectionError):
    """The request timed out."""


class APIError(EyalSecError):
    """The API answered with an error status.

    Attributes:
        status: The HTTP status code.
        message: The server's short message (the ``error`` field of a JSON
            body, or the plain-text body), or ``""`` when there was none.
        method: The HTTP method of the request.
        path: The path of the request, without the query string.
        body: The decoded JSON body when there was one, else ``None``.
    """

    def __init__(
        self,
        status: int,
        message: str = "",
        *,
        method: str = "",
        path: str = "",
        body: Optional[Any] = None,
        retry_after: Optional[float] = None,
    ) -> None:
        self.status = status
        self.message = message
        self.method = method
        self.path = path
        self.body = body
        self.retry_after = retry_after
        super().__init__(self._describe())

    def _hint(self) -> str:
        return ""

    def _describe(self) -> str:
        where = f" ({self.method} {self.path})" if self.path else ""
        text = f"EyalSec API answered {self.status}{where}"
        if self.message:
            text += f": {self.message}"
        hint = self._hint()
        if hint:
            text += f". {hint}"
        return text


class BadRequestError(APIError):
    """400: malformed JSON, an invalid regex, an unreadable cursor or date, or
    an unknown value such as a ``view`` that does not exist."""


class AuthenticationError(APIError):
    """401: the API key is missing, wrong, revoked or expired."""

    def _hint(self) -> str:
        return "Create a key on your dashboard under Settings > API access"


class PermissionDeniedError(APIError):
    """403: a read-only key trying to write, a product or feature not enabled
    on the account, a wrong password on an account call, or a write on an
    account limited to reading."""


class NotFoundError(APIError):
    """404: not found. The API answers the same way for something that belongs
    to another account, so its existence is never confirmed.

    ``unavailable`` is ``True`` when the address answered with its generic
    "no such page" rather than an API error: the endpoint is not offered by
    that EyalSec address (for example, one still running an older release).
    """

    def __init__(self, *args: Any, unavailable: bool = False, **kwargs: Any) -> None:
        self.unavailable = unavailable
        super().__init__(*args, **kwargs)

    def _hint(self) -> str:
        if self.unavailable:
            return "This EyalSec address does not offer this endpoint"
        return ""


class ConflictError(APIError):
    """409: a conflict with the current state, such as the machine limit being
    reached or a label name already in use."""


class UnprocessableEntityError(APIError):
    """422: a field is missing or invalid, such as an unknown OS target or a
    missing install confirmation."""


class RateLimitError(APIError):
    """429: a rate limit was hit, or the account is locked after wrong
    passwords. ``retry_after`` is the number of seconds the server asked to
    wait, when it said."""

    def _hint(self) -> str:
        if self.retry_after is not None:
            return f"Try again in {self.retry_after:g} seconds"
        return ""


class InternalServerError(APIError):
    """5xx: something failed on the EyalSec side. Try again, and contact
    support@eyalsec.com if it persists."""


class UnexpectedResponseError(APIError):
    """The answer had a success status but could not be read: not JSON where
    JSON was expected, or a redirect (the API never redirects a key request,
    so a redirect means the address or path is wrong)."""


_BY_STATUS: Dict[int, Type[APIError]] = {
    400: BadRequestError,
    401: AuthenticationError,
    403: PermissionDeniedError,
    404: NotFoundError,
    409: ConflictError,
    422: UnprocessableEntityError,
    429: RateLimitError,
}


def error_class_for(status: int) -> Type[APIError]:
    if status >= 500:
        return InternalServerError
    return _BY_STATUS.get(status, APIError)
