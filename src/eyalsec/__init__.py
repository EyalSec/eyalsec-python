"""Python client for the EyalSec API.

Read your security events, machines and runs, and manage rules, filters,
labels and settings, from Python::

    import eyalsec

    client = eyalsec.EyalSec()  # reads EYALSEC_API_KEY
    for event in client.iter_events(severity=["critical", "high"]):
        print(event.created_at, event.where, event.machine_name)

``AsyncEyalSec`` has the same methods for ``asyncio``.

This package is the API client. It is not es-python, the EyalSec Python
runtime, and importing it adds no security checks to your program; the
runtime is installed from your EyalSec dashboard
(https://eyalsec.com/docs/quick-start).
"""

from enum import IntEnum

from ._async_client import AsyncEyalSec
from ._base import API_KEY_ENV, BASE_URL_ENV, DEFAULT_BASE_URL
from ._client import EyalSec
from ._errors import (
    APIConnectionError,
    APIError,
    APITimeoutError,
    AuthenticationError,
    BadRequestError,
    ConfigurationError,
    ConflictError,
    EyalSecError,
    InternalServerError,
    NotFoundError,
    PermissionDeniedError,
    RateLimitError,
    UnexpectedResponseError,
    UnprocessableEntityError,
)
from ._models import (
    Account,
    ActivityEntry,
    ActivityPage,
    APIKeyInfo,
    BlockedClient,
    CIFinding,
    CIFindings,
    CIInstall,
    Distro,
    Event,
    EventCount,
    EventDetail,
    EventPage,
    EventRun,
    EventStats,
    EventUniqueness,
    Extension,
    Filter,
    HiddenBy,
    Impact,
    InstallCommand,
    Label,
    Machine,
    NewMachine,
    OnboardingState,
    PythonVersions,
    Rule,
    RuleTemplate,
    RuleTemplateList,
    Run,
    RunPage,
    SavedSearch,
    TemplateApplyResult,
    TemplateCategory,
    TemplateItem,
    parse_time,
)
from ._version import __version__


class RuleMode(IntEnum):
    """What a machine rule does with the events it matches."""

    HIDE = 1
    SHOW = 2
    RAISE = 3
    DONT_SEND = 4


HOMEPAGE = "https://eyalsec.com"
DOCS = "https://eyalsec.com/docs"
API_DOCS = "https://eyalsec.com/docs/api"
QUICK_START = "https://eyalsec.com/docs/quick-start"
PRICING = "https://eyalsec.com/pricing"
CONTACT = "https://eyalsec.com/contact"
GITHUB = "https://github.com/EyalSec"
SDK_DOCS = "https://eyalsec.readthedocs.io"


class EyalSecNoticeWarning(UserWarning):
    """Kept so that code written for eyalsec 1.0, which filtered this warning,
    still imports. Nothing issues it any more."""


def about() -> str:
    """Return a short description of this package, with links."""
    return f"""\
eyalsec {__version__}: the Python client for the EyalSec API.

It reads your EyalSec events, machines and runs, and manages rules, filters,
labels and settings, with an API key from Settings > API access.

It is not es-python, the EyalSec Python runtime, and importing it adds no
security checks to your program. The runtime is installed from your EyalSec
dashboard: {QUICK_START}

  Client docs   {SDK_DOCS}
  API reference {API_DOCS}
  Pricing       {PRICING}
  Book a demo   {CONTACT}
  Website       {HOMEPAGE}

Questions: support@eyalsec.com"""


__all__ = [
    "__version__",
    "EyalSec",
    "AsyncEyalSec",
    "RuleMode",
    "about",
    "API_KEY_ENV",
    "BASE_URL_ENV",
    "DEFAULT_BASE_URL",
    # errors
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
    # models
    "Account",
    "ActivityEntry",
    "ActivityPage",
    "APIKeyInfo",
    "BlockedClient",
    "CIFinding",
    "CIFindings",
    "CIInstall",
    "Distro",
    "Event",
    "EventCount",
    "EventDetail",
    "EventPage",
    "EventRun",
    "EventStats",
    "EventUniqueness",
    "Extension",
    "Filter",
    "HiddenBy",
    "Impact",
    "InstallCommand",
    "Label",
    "Machine",
    "NewMachine",
    "OnboardingState",
    "PythonVersions",
    "Rule",
    "RuleTemplate",
    "RuleTemplateList",
    "Run",
    "RunPage",
    "SavedSearch",
    "TemplateApplyResult",
    "TemplateCategory",
    "TemplateItem",
    "parse_time",
    # 1.0 compatibility
    "EyalSecNoticeWarning",
    "HOMEPAGE",
    "DOCS",
    "API_DOCS",
    "QUICK_START",
    "PRICING",
    "CONTACT",
    "GITHUB",
    "SDK_DOCS",
]
