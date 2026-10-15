"""Pieces shared by the sync and async clients: configuration, request
bodies, and turning an answer into a value or an exception."""

from __future__ import annotations

import os
import random
from datetime import date, datetime
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union
from urllib.parse import urlsplit

import httpx

from ._errors import (
    APIError,
    ConfigurationError,
    NotFoundError,
    UnexpectedResponseError,
    error_class_for,
)
from ._version import __version__

DEFAULT_BASE_URL = "https://eyalsec.com"
API_KEY_ENV = "EYALSEC_API_KEY"
BASE_URL_ENV = "EYALSEC_URL"
DEFAULT_TIMEOUT = 30.0
DEFAULT_MAX_RETRIES = 2
MAX_RETRY_WAIT = 60.0

_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

#: Endpoints that are reads although they are POSTs (their filters travel in
#: the body), so retrying them after a dropped connection is safe.
IDEMPOTENT_POSTS = frozenset({"/api/get_all_events_with_count/", "/api/event_map/", "/api/events_export"})

DateLike = Union[str, date, datetime]
StrList = Union[str, Sequence[str]]


def resolve_api_key(api_key: Optional[str]) -> str:
    key = api_key if api_key is not None else os.environ.get(API_KEY_ENV, "")
    return (key or "").strip()


def normalize_base_url(url: Optional[str]) -> str:
    """Return the origin to call, without a trailing slash.

    Plain ``http://`` is refused for anything but this machine, because the
    API key would travel in clear text.
    """
    if url is None:
        url = os.environ.get(BASE_URL_ENV, "")
    url = (url or "").strip().rstrip("/")
    if not url:
        return DEFAULT_BASE_URL
    parts = urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.hostname:
        raise ConfigurationError(f"base_url must be an https:// address, got {url!r}")
    if parts.scheme == "http" and parts.hostname not in _LOCAL_HOSTS:
        raise ConfigurationError(f"base_url must use https:// (the API key would be sent in clear text), got {url!r}")
    return url


def user_agent(extra: Optional[str] = None) -> str:
    ua = f"eyalsec-python/{__version__} httpx/{httpx.__version__}"
    return f"{ua} {extra}" if extra else ua


def missing_key_error() -> ConfigurationError:
    return ConfigurationError(
        f"No API key. Pass api_key=... or set {API_KEY_ENV}. Create a key on your EyalSec "
        "dashboard under Settings > API access (a read-only key is enough for reads)."
    )


# --------------------------------------------------------------------------- bodies


def _date(v: DateLike) -> str:
    if isinstance(v, datetime):
        return v.isoformat().replace("+00:00", "Z")
    if isinstance(v, date):
        return v.isoformat()
    return str(v)


def _strs(v: Optional[StrList]) -> Optional[List[str]]:
    if v is None:
        return None
    if isinstance(v, str):
        return [p.strip() for p in v.split(",") if p.strip()]
    return [str(x) for x in v]


def event_filters(
    *,
    view: Optional[str] = None,
    bucket: Optional[str] = None,
    sort: Optional[str] = None,
    from_date: Optional[DateLike] = None,
    to_date: Optional[DateLike] = None,
    machine: Optional[str] = None,
    severity: Optional[StrList] = None,
    sources: Optional[StrList] = None,
    tags: Optional[StrList] = None,
    labels: Optional[Sequence[int]] = None,
    whitelist_repr: Optional[str] = None,
    blacklist_repr: Optional[str] = None,
    xss_only: Optional[bool] = None,
    scope: Optional[Mapping[str, Any]] = None,
    advanced: Optional[Mapping[str, Any]] = None,
    run: Optional[str] = None,
    extra: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the JSON body shared by the events query, export and map.

    Only the filters you pass are sent. ``run`` is a shortcut for a ``run``
    condition in ``advanced``.
    """
    body: Dict[str, Any] = {}
    if view:
        body["view"] = view
    if bucket:
        body["bucket"] = bucket
    if sort:
        body["sort"] = sort
    if from_date is not None:
        body["from"] = _date(from_date)
    if to_date is not None:
        body["to"] = _date(to_date)
    if machine:
        body["machine"] = machine
    for name, value in (("severity", severity), ("sources", sources), ("tags", tags)):
        listed = _strs(value)
        if listed is not None:
            body[name] = listed
    if labels is not None:
        body["labels"] = [int(x) for x in labels]
    if whitelist_repr:
        body["whitelist_repr"] = whitelist_repr
    if blacklist_repr:
        body["blacklist_repr"] = blacklist_repr
    if xss_only is not None:
        body["xss_only"] = bool(xss_only)
    if scope is not None:
        body["scope"] = dict(scope)
    adv: Optional[Dict[str, Any]] = None
    if advanced is not None:
        adv = {**advanced, "conditions": list(advanced.get("conditions") or [])}
    if run:
        if adv is None:
            adv = {"match": "all", "conditions": []}
        elif adv.get("match", "all") != "all":
            raise ValueError('run= needs advanced["match"] == "all"; add the run condition to advanced yourself')
        adv["conditions"].append({"field": "run", "op": "is", "value": run})
    if adv is not None:
        body["advanced"] = adv
    if extra:
        body.update(extra)
    return body


def form(**fields: Any) -> Dict[str, str]:
    """Form fields, dropping ``None`` and rendering booleans as the API expects."""
    out: Dict[str, str] = {}
    for k, v in fields.items():
        if v is None:
            continue
        if isinstance(v, bool):
            out[k] = "true" if v else "false"
        else:
            out[k] = str(v)
    return out


def params(**fields: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in fields.items():
        if v is None:
            continue
        if isinstance(v, bool):
            out[k] = "true" if v else "false"
        elif isinstance(v, (date, datetime)):
            out[k] = _date(v)
        else:
            out[k] = str(v)
    return out


def machine_param(machine: Optional[str]) -> str:
    """``None`` and ``""`` both mean the global scope."""
    return machine or ""


# --------------------------------------------------------------------------- answers


def parse_retry_after(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    now = datetime.now(when.tzinfo)
    return max(0.0, (when - now).total_seconds())


def retry_wait(attempt: int, retry_after: Optional[float]) -> float:
    """Seconds to wait before retry number ``attempt`` (1-based)."""
    if retry_after is not None:
        return min(retry_after, MAX_RETRY_WAIT)
    base: float = min(0.5 * (2 ** (attempt - 1)), 8.0)
    return base + random.uniform(0, base / 4)


def is_retryable_status(status: int) -> bool:
    return status in (429, 502, 503, 504)


def _error_message(resp: httpx.Response) -> tuple[str, Any]:
    body: Any = None
    ctype = resp.headers.get("content-type", "")
    if "json" in ctype:
        try:
            body = resp.json()
        except ValueError:
            body = None
        if isinstance(body, dict):
            for key in ("error", "message", "detail"):
                if body.get(key):
                    return str(body[key])[:1000], body
    text = resp.text.strip()
    if text.startswith("<") or "html" in ctype:
        return "", body
    return text[:1000], body


def raise_for_response(resp: httpx.Response, method: str, path: str) -> None:
    """Raise the matching :class:`APIError` for an error or a redirect."""
    if resp.is_redirect:
        raise UnexpectedResponseError(
            resp.status_code,
            f"unexpected redirect to {resp.headers.get('location', '?')}; check base_url",
            method=method,
            path=path,
        )
    if resp.status_code < 400:
        return
    message, body = _error_message(resp)
    cls = error_class_for(resp.status_code)
    retry_after = parse_retry_after(resp.headers.get("retry-after"))
    if cls is NotFoundError:
        unavailable = "html" in resp.headers.get("content-type", "")
        raise NotFoundError(
            resp.status_code,
            message,
            method=method,
            path=path,
            body=body,
            retry_after=retry_after,
            unavailable=unavailable,
        )
    raise cls(resp.status_code, message, method=method, path=path, body=body, retry_after=retry_after)


def decode_json(resp: httpx.Response, method: str, path: str) -> Any:
    if resp.status_code == 204 or not resp.content:
        return {}
    try:
        return resp.json()
    except ValueError as exc:
        raise UnexpectedResponseError(resp.status_code, "the answer was not JSON", method=method, path=path) from exc


def as_dict(value: Any, method: str, path: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise UnexpectedResponseError(200, "expected a JSON object", method=method, path=path, body=value)
    return value


__all__ = [
    "APIError",
    "DEFAULT_BASE_URL",
    "API_KEY_ENV",
    "BASE_URL_ENV",
    "event_filters",
]
