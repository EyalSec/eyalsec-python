"""Typed records for what the API returns.

Every record is a frozen dataclass built from the API's JSON. Each keeps the
JSON it was built from in ``raw``, so a field the server adds after this
version of the library is still reachable. Rows the API sends as arrays (an
event, a machine) are read by position, as the API reference asks, and any
values past the known ones are kept in ``extra``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

__all__ = [
    "parse_time",
    "Impact",
    "Label",
    "Event",
    "HiddenBy",
    "EventPage",
    "Extension",
    "EventRun",
    "EventDetail",
    "Run",
    "RunPage",
    "EventStats",
    "EventCount",
    "SavedSearch",
    "Machine",
    "NewMachine",
    "InstallCommand",
    "Distro",
    "PythonVersions",
    "CIInstall",
    "CIFinding",
    "CIFindings",
    "Filter",
    "Rule",
    "TemplateItem",
    "TemplateCategory",
    "RuleTemplate",
    "RuleTemplateList",
    "TemplateApplyResult",
    "EventUniqueness",
    "BlockedClient",
    "ActivityEntry",
    "ActivityPage",
    "Account",
    "APIKeyInfo",
    "OnboardingState",
]

_FRACTION = re.compile(r"\.(\d+)")


def parse_time(value: Any) -> Optional[datetime]:
    """Parse an RFC 3339 timestamp from the API into an aware ``datetime``.

    Returns ``None`` for an empty or missing value. Fractions finer than a
    microsecond are truncated, since ``datetime`` cannot hold them.
    """
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    text = _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), text, count=1)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _s(d: Mapping[str, Any], key: str) -> str:
    v = d.get(key)
    return "" if v is None else str(v)


def _i(d: Mapping[str, Any], key: str, default: int = 0) -> int:
    v = d.get(key)
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, (int, float)):
        return int(v)
    if isinstance(v, str):
        try:
            return int(v)
        except ValueError:
            return default
    return default


def _b(d: Mapping[str, Any], key: str) -> bool:
    v = d.get(key)
    if isinstance(v, str):
        return v.strip().lower() == "true"
    return bool(v)


def _list(v: Any) -> List[Any]:
    return list(v) if isinstance(v, (list, tuple)) else []


def _dict(v: Any) -> Dict[str, Any]:
    return dict(v) if isinstance(v, Mapping) else {}


def _at(row: Sequence[Any], i: int, default: Any = None) -> Any:
    return row[i] if i < len(row) else default


# --------------------------------------------------------------------------- events


@dataclass(frozen=True)
class Impact:
    """One impact class on an event, such as ``command injection``."""

    label: str
    sev: str

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Impact:
        return cls(label=_s(d, "label"), sev=_s(d, "sev"))


@dataclass(frozen=True)
class Label:
    """One of your triage labels."""

    id: int
    name: str
    color: str
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Label:
        return cls(id=_i(d, "id"), name=_s(d, "name"), color=_s(d, "color"), raw=dict(d))


EVENT_ROW_FIELDS: Tuple[str, ...] = (
    "created_at",
    "where",
    "str_repr",
    "count",
    "machine_name",
    "severity",
    "agent_kind",
    "id",
    "source_label",
    "context",
    "suppressed",
    "sanitize_reason",
    "impact",
    "labels",
    "has_comment",
    "extension",
    "taint_source",
)


@dataclass(frozen=True)
class Event:
    """One event from the events list.

    The field names follow the API reference's event row. ``where`` is the
    sink label (what happened), ``str_repr`` the value that reached it, and
    ``id`` the number to pass to :meth:`EyalSec.get_event` for the stack
    trace and the rest of the detail.
    """

    id: int
    created_at: Optional[datetime]
    where: str
    str_repr: str
    count: int
    machine_name: str
    severity: str
    agent_kind: str
    source_label: str = ""
    context: str = ""
    suppressed: bool = False
    sanitize_reason: str = ""
    impact: Tuple[Impact, ...] = ()
    labels: Tuple[Label, ...] = ()
    has_comment: bool = False
    extension: str = ""
    taint_source: str = ""
    extra: Tuple[Any, ...] = field(default=(), repr=False)
    raw: Sequence[Any] = field(default=(), repr=False, compare=False)

    @classmethod
    def from_row(cls, row: Sequence[Any]) -> Event:
        if isinstance(row, Mapping):  # tolerate an object form
            row = [row.get(name) for name in EVENT_ROW_FIELDS]
        row = list(row)
        d = {name: _at(row, i) for i, name in enumerate(EVENT_ROW_FIELDS)}
        return cls(
            id=_i(d, "id"),
            created_at=parse_time(d["created_at"]),
            where=_s(d, "where"),
            str_repr=_s(d, "str_repr"),
            count=_i(d, "count"),
            machine_name=_s(d, "machine_name"),
            severity=_s(d, "severity"),
            agent_kind=_s(d, "agent_kind"),
            source_label=_s(d, "source_label"),
            context=_s(d, "context"),
            suppressed=_b(d, "suppressed"),
            sanitize_reason=_s(d, "sanitize_reason"),
            impact=tuple(Impact.from_dict(x) for x in _list(d["impact"]) if isinstance(x, Mapping)),
            labels=tuple(Label.from_dict(x) for x in _list(d["labels"]) if isinstance(x, Mapping)),
            has_comment=_b(d, "has_comment"),
            extension=_s(d, "extension"),
            taint_source=_s(d, "taint_source"),
            extra=tuple(row[len(EVENT_ROW_FIELDS) :]),
            raw=tuple(row),
        )


@dataclass(frozen=True)
class HiddenBy:
    """The Hide rule that hides every event in the view."""

    id: int
    label: str

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> HiddenBy:
        return cls(id=_i(d, "id"), label=_s(d, "label"))


@dataclass(frozen=True)
class EventPage:
    """One page of the events query.

    A short or empty page is not the last page: keep going while
    ``next_cursor`` is non-empty (:attr:`has_more`). :meth:`EyalSec.iter_events`
    does that for you.
    """

    events: Tuple[Event, ...]
    next_cursor: str
    scanned: int
    exhausted: bool
    oldest_examined: Optional[datetime]
    event_limit: int
    event_limit_monthly: bool
    hidden_by: Optional[HiddenBy] = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @property
    def has_more(self) -> bool:
        """``True`` while there is another page to ask for."""
        return bool(self.next_cursor)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> EventPage:
        hb = d.get("hidden_by")
        return cls(
            events=tuple(Event.from_row(r) for r in _list(d.get("events"))),
            next_cursor=_s(d, "next_cursor"),
            scanned=_i(d, "scanned"),
            exhausted=_b(d, "exhausted"),
            oldest_examined=parse_time(d.get("oldest_examined")),
            event_limit=_i(d, "event_limit", -1),
            event_limit_monthly=_b(d, "event_limit_monthly"),
            hidden_by=HiddenBy.from_dict(hb) if isinstance(hb, Mapping) else None,
            raw=dict(d),
        )


@dataclass(frozen=True)
class Extension:
    """The browser extension an es-chromium event came from. All fields are
    empty when no extension was involved."""

    id: str = ""
    name: str = ""
    version: str = ""
    label: str = ""

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Extension:
        return cls(id=_s(d, "id"), name=_s(d, "name"), version=_s(d, "version"), label=_s(d, "label"))


@dataclass(frozen=True)
class EventRun:
    """One program invocation that produced an event."""

    run_uid: str
    cmdline: str
    env: str
    count: int
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> EventRun:
        return cls(
            run_uid=_s(d, "run_uid"),
            cmdline=_s(d, "cmdline"),
            env=_s(d, "env"),
            count=_i(d, "count"),
            first_seen=parse_time(d.get("first_seen")),
            last_seen=parse_time(d.get("last_seen")),
        )


@dataclass(frozen=True)
class EventDetail:
    """The large fields of one event that the events list leaves out."""

    trace: str
    origin: str
    repr_created: str
    source_code: str
    sink_code: str
    detail: str
    comment: str
    rule_source: str
    extension: Extension
    runs: Tuple[EventRun, ...]
    source: str = ""
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> EventDetail:
        return cls(
            trace=_s(d, "trace"),
            origin=_s(d, "origin"),
            repr_created=_s(d, "repr_created"),
            source_code=_s(d, "source_code"),
            sink_code=_s(d, "sink_code"),
            detail=_s(d, "detail"),
            comment=_s(d, "comment"),
            rule_source=_s(d, "rule_source"),
            extension=Extension.from_dict(_dict(d.get("extension"))),
            runs=tuple(EventRun.from_dict(r) for r in _list(d.get("runs")) if isinstance(r, Mapping)),
            source=_s(d, "source"),
            raw=dict(d),
        )


@dataclass(frozen=True)
class Run:
    """One invocation of one monitored program, from the runs list."""

    run_uid: str
    cmdline: str
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    events: int
    occurrences: int
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Run:
        return cls(
            run_uid=_s(d, "run_uid"),
            cmdline=_s(d, "cmdline"),
            first_seen=parse_time(d.get("first_seen")),
            last_seen=parse_time(d.get("last_seen")),
            events=_i(d, "events"),
            occurrences=_i(d, "occurrences"),
            raw=dict(d),
        )


@dataclass(frozen=True)
class RunPage:
    """One page of the runs list. Pass ``next_before`` back to get the next."""

    runs: Tuple[Run, ...]
    next_before: str
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @property
    def has_more(self) -> bool:
        return bool(self.next_before)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> RunPage:
        return cls(
            runs=tuple(Run.from_dict(r) for r in _list(d.get("runs")) if isinstance(r, Mapping)),
            next_before=_s(d, "next_before"),
            raw=dict(d),
        )


@dataclass(frozen=True)
class EventStats:
    """The summary the dashboard shows. ``top_events``, ``recent`` and
    ``timeline_14d`` are lists of plain dicts as the API sends them."""

    total_hits: int
    unique_types: int
    last_1h: int
    last_24h: int
    last_7d: int
    top_events: Tuple[Mapping[str, Any], ...]
    recent: Tuple[Mapping[str, Any], ...]
    timeline_14d: Tuple[Mapping[str, Any], ...]
    first_detection: Optional[datetime]
    latest_detection: Optional[datetime]
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> EventStats:
        return cls(
            total_hits=_i(d, "total_hits"),
            unique_types=_i(d, "unique_types"),
            last_1h=_i(d, "last_1h"),
            last_24h=_i(d, "last_24h"),
            last_7d=_i(d, "last_7d"),
            top_events=tuple(_dict(x) for x in _list(d.get("top_events"))),
            recent=tuple(_dict(x) for x in _list(d.get("recent"))),
            timeline_14d=tuple(_dict(x) for x in _list(d.get("timeline_14d"))),
            first_detection=parse_time(d.get("first_detection")),
            latest_detection=parse_time(d.get("latest_detection")),
            raw=dict(d),
        )


@dataclass(frozen=True)
class EventCount:
    """How many stored events count toward the quota period, and the limit."""

    count: int
    view: str
    event_limit: int
    event_limit_monthly: bool
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> EventCount:
        return cls(
            count=_i(d, "count"),
            view=_s(d, "view"),
            event_limit=_i(d, "event_limit", -1),
            event_limit_monthly=_b(d, "event_limit_monthly"),
            raw=dict(d),
        )


@dataclass(frozen=True)
class SavedSearch:
    """A named events-page query string."""

    id: int
    name: str
    view: str
    query: str

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> SavedSearch:
        return cls(id=_i(d, "id"), name=_s(d, "name"), view=_s(d, "view"), query=_s(d, "query"))


# --------------------------------------------------------------------------- machines

MACHINE_ROW_FIELDS: Tuple[str, ...] = (
    "created_at",
    "machine_name",
    "status",
    "public_id",
    "os_type",
    "installed_build",
    "current_build",
    "python_version",
    "socket_only",
    "clone_locked",
    "stalled",
    "stale_agent",
    "agent_kind",
)


@dataclass(frozen=True)
class Machine:
    """One machine on the account. ``public_id`` is its handle in every other
    call; the machine's secret is never returned by the API."""

    public_id: str
    machine_name: str
    status: str
    created_at: Optional[datetime]
    os_type: str
    installed_build: str
    current_build: str
    python_version: str
    clone_locked: bool
    stalled: bool
    stale_agent: bool
    agent_kind: str
    socket_only: bool = False
    extra: Tuple[Any, ...] = field(default=(), repr=False)
    raw: Sequence[Any] = field(default=(), repr=False, compare=False)

    @property
    def update_available(self) -> bool:
        """``True`` when a newer build than the installed one is available."""
        return bool(self.installed_build and self.current_build and self.installed_build != self.current_build)

    @classmethod
    def from_row(cls, row: Sequence[Any]) -> Machine:
        if isinstance(row, Mapping):
            row = [row.get(name) for name in MACHINE_ROW_FIELDS]
        row = list(row)
        d = {name: _at(row, i) for i, name in enumerate(MACHINE_ROW_FIELDS)}
        return cls(
            public_id=_s(d, "public_id"),
            machine_name=_s(d, "machine_name"),
            status=_s(d, "status"),
            created_at=parse_time(d["created_at"]),
            os_type=_s(d, "os_type"),
            installed_build=_s(d, "installed_build"),
            current_build=_s(d, "current_build"),
            python_version=_s(d, "python_version"),
            socket_only=_b(d, "socket_only"),
            clone_locked=_b(d, "clone_locked"),
            stalled=_b(d, "stalled"),
            stale_agent=_b(d, "stale_agent"),
            agent_kind=_s(d, "agent_kind"),
            extra=tuple(row[len(MACHINE_ROW_FIELDS) :]),
            raw=tuple(row),
        )


@dataclass(frozen=True)
class NewMachine:
    """The machine :meth:`EyalSec.add_machine` just registered."""

    public_id: str
    name: str
    status: str
    os_type: str
    python_version: str
    agent_kind: str
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> NewMachine:
        return cls(
            public_id=_s(d, "PublicID"),
            name=_s(d, "Name"),
            status=_s(d, "Status"),
            os_type=_s(d, "OsType"),
            python_version=_s(d, "PythonVersion"),
            agent_kind=_s(d, "AgentKind"),
            raw=dict(d),
        )


@dataclass(frozen=True)
class InstallCommand:
    """A one-time install or uninstall secret and the script to post it to.

    The secret works once and expires after ``expires_in`` seconds. Treat it
    like a password.
    """

    secret: str = field(repr=False)
    script_path: str
    os_type: str = ""
    expires_in: Optional[int] = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> InstallCommand:
        return cls(
            secret=_s(d, "secret"),
            script_path=_s(d, "script_path"),
            os_type=_s(d, "os_type"),
            expires_in=_i(d, "expires_in") if "expires_in" in d else None,
            raw=dict(d),
        )


@dataclass(frozen=True)
class Distro:
    """A Linux distribution es-python installs on, and its architectures."""

    id: str
    label: str
    archs: Tuple[str, ...]

    def os_types(self) -> List[str]:
        """The ``os_type`` values for this distribution, such as ``ubuntu_24_04_x86_64``."""
        return [f"{self.id}_{a}" for a in self.archs]

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Distro:
        return cls(id=_s(d, "id"), label=_s(d, "label"), archs=tuple(str(a) for a in _list(d.get("archs"))))


@dataclass(frozen=True)
class PythonVersions:
    """The Python versions on offer, and the default."""

    versions: Tuple[str, ...]
    default: str

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> PythonVersions:
        return cls(versions=tuple(str(v) for v in _list(d.get("versions"))), default=_s(d, "default"))


# --------------------------------------------------------------------------- CI


@dataclass(frozen=True)
class CIInstall:
    """What :meth:`EyalSec.ci_install` returns: a one-time install secret for
    the runner, and the server's clock to pass to :meth:`EyalSec.ci_findings`."""

    machine_name: str
    public_id: str
    created: bool
    os_type: str
    python_version: str
    secret: str = field(repr=False)
    script_path: str
    expires_in: int
    server_time: str
    events_url: str
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> CIInstall:
        return cls(
            machine_name=_s(d, "machine_name"),
            public_id=_s(d, "public_id"),
            created=_b(d, "created"),
            os_type=_s(d, "os_type"),
            python_version=_s(d, "python_version"),
            secret=_s(d, "secret"),
            script_path=_s(d, "script_path"),
            expires_in=_i(d, "expires_in"),
            server_time=_s(d, "server_time"),
            events_url=_s(d, "events_url"),
            raw=dict(d),
        )


@dataclass(frozen=True)
class CIFinding:
    """One finding in a CI check. The value that reached the sink is
    deliberately left out, because CI logs are often public."""

    id: int
    severity: str
    where: str
    count: int
    last_seen: Optional[datetime]
    new: bool

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> CIFinding:
        return cls(
            id=_i(d, "id"),
            severity=_s(d, "severity"),
            where=_s(d, "where"),
            count=_i(d, "count"),
            last_seen=parse_time(d.get("last_seen")),
            new=_b(d, "new"),
        )


@dataclass(frozen=True)
class CIFindings:
    """What runs on one machine reported since a moment."""

    machine: str
    since: str
    min_severity: str
    findings: int
    new_findings: int
    total: int
    by_severity: Mapping[str, int]
    truncated: bool
    hidden_by: str
    url: str
    events: Tuple[CIFinding, ...]
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> CIFindings:
        bs = _dict(d.get("by_severity"))
        return cls(
            machine=_s(d, "machine"),
            since=_s(d, "since"),
            min_severity=_s(d, "min_severity"),
            findings=_i(d, "findings"),
            new_findings=_i(d, "new_findings"),
            total=_i(d, "total"),
            by_severity={str(k): _i(bs, k) for k in bs},
            truncated=_b(d, "truncated"),
            hidden_by=_s(d, "hidden_by"),
            url=_s(d, "url"),
            events=tuple(CIFinding.from_dict(e) for e in _list(d.get("events")) if isinstance(e, Mapping)),
            raw=dict(d),
        )


# --------------------------------------------------------------------------- filters, rules, templates


@dataclass(frozen=True)
class Filter:
    """An event filter from a Filters page."""

    id: int
    pattern: str
    mode: str
    target: str
    enabled: bool
    label: str = ""
    engine: str = ""
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Filter:
        return cls(
            id=_i(d, "id"),
            pattern=_s(d, "pattern"),
            mode=_s(d, "mode"),
            target=_s(d, "target"),
            enabled=_b(d, "enabled"),
            label=_s(d, "label"),
            engine=_s(d, "engine"),
            raw=dict(d),
        )


def _pick(d: Mapping[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in d:
            return d[k]
    return None


@dataclass(frozen=True)
class Rule:
    """A machine rule. ``mode`` decides what it does: ``1`` Hide, ``2`` Show,
    ``3`` Raise, ``4`` Don't send (see :data:`eyalsec.RuleMode`)."""

    id: int
    mode: int
    source: str
    event_pattern: str
    label: str
    enabled: bool
    sanitize_scope: str
    match_on: Tuple[str, ...] = ()
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Rule:
        # Rule fields are capitalized on the wire, except sanitize_scope and
        # match_on; accept either spelling.
        n = {
            "id": _pick(d, "ID", "id"),
            "mode": _pick(d, "Mode", "mode"),
            "source": _pick(d, "Source", "source"),
            "event_pattern": _pick(d, "EventPattern", "event_pattern"),
            "label": _pick(d, "Label", "label"),
            "enabled": _pick(d, "Enabled", "enabled"),
        }
        return cls(
            id=_i(n, "id"),
            mode=_i(n, "mode"),
            source=_s(n, "source"),
            event_pattern=_s(n, "event_pattern"),
            label=_s(n, "label"),
            enabled=_b(n, "enabled"),
            sanitize_scope=_s(d, "sanitize_scope") or "any",
            match_on=tuple(str(x) for x in _list(d.get("match_on"))),
            raw=dict(d),
        )


@dataclass(frozen=True)
class TemplateItem:
    """One rule inside a rule template."""

    source: str
    event_pattern: str
    mode: int
    sanitize_scope: str = "any"
    position: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "event_pattern": self.event_pattern,
            "mode": self.mode,
            "sanitize_scope": self.sanitize_scope,
        }

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> TemplateItem:
        return cls(
            source=_s(d, "source"),
            event_pattern=_s(d, "event_pattern"),
            mode=_i(d, "mode"),
            sanitize_scope=_s(d, "sanitize_scope") or "any",
            position=_i(d, "position"),
        )


@dataclass(frozen=True)
class TemplateCategory:
    """A category on the Templates page."""

    key: str
    name: str
    blurb: str

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> TemplateCategory:
        return cls(key=_s(d, "key"), name=_s(d, "name"), blurb=_s(d, "blurb"))


@dataclass(frozen=True)
class RuleTemplate:
    """A rule template. ``owner`` is ``"me"`` for your own and ``"eyalsec"``
    for the published ones, which you can apply but not change."""

    id: int
    owner: str
    name: str
    description: str
    items: Tuple[TemplateItem, ...]
    product: str = ""
    category: str = ""
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> RuleTemplate:
        return cls(
            id=_i(d, "id"),
            owner=_s(d, "owner"),
            name=_s(d, "name"),
            description=_s(d, "description"),
            items=tuple(TemplateItem.from_dict(x) for x in _list(d.get("items")) if isinstance(x, Mapping)),
            product=_s(d, "product"),
            category=_s(d, "category"),
            raw=dict(d),
        )


@dataclass(frozen=True)
class RuleTemplateList:
    """Every template you can see, and the categories the page lists them under."""

    templates: Tuple[RuleTemplate, ...]
    categories: Tuple[TemplateCategory, ...]

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> RuleTemplateList:
        return cls(
            templates=tuple(RuleTemplate.from_dict(t) for t in _list(d.get("templates")) if isinstance(t, Mapping)),
            categories=tuple(
                TemplateCategory.from_dict(c) for c in _list(d.get("categories")) if isinstance(c, Mapping)
            ),
        )


@dataclass(frozen=True)
class TemplateApplyResult:
    """What applying a template did. Skipped items are counted, so a partial
    apply is never silent."""

    added: int
    skipped_raise: int
    skipped_duplicate: int

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> TemplateApplyResult:
        return cls(
            added=_i(d, "added"),
            skipped_raise=_i(d, "skipped_raise"),
            skipped_duplicate=_i(d, "skipped_duplicate"),
        )


@dataclass(frozen=True)
class EventUniqueness:
    """The unique-event definition in force for one product and scope."""

    agent_kind: str
    machine: str
    axes: Tuple[str, ...]
    inherited: bool
    available: Tuple[str, ...]
    baseline: Tuple[str, ...]

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> EventUniqueness:
        return cls(
            agent_kind=_s(d, "agent_kind"),
            machine=_s(d, "machine"),
            axes=tuple(str(x) for x in _list(d.get("axes"))),
            inherited=_b(d, "inherited"),
            available=tuple(str(x) for x in _list(d.get("available"))),
            baseline=tuple(str(x) for x in _list(d.get("baseline"))),
        )


@dataclass(frozen=True)
class BlockedClient:
    """An address or range on your web protection blocklist."""

    id: int
    address: str
    source: str
    reason: str
    created_at: Optional[datetime]
    expires_at: Optional[datetime]
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> BlockedClient:
        return cls(
            id=_i(d, "id"),
            address=_s(d, "address"),
            source=_s(d, "source"),
            reason=_s(d, "reason"),
            created_at=parse_time(d.get("created_at")),
            expires_at=parse_time(d.get("expires_at")),
            raw=dict(d),
        )


# --------------------------------------------------------------------------- account


@dataclass(frozen=True)
class ActivityEntry:
    """One entry of the activity log."""

    id: int
    time: Optional[datetime]
    action: str
    description: str
    target: str
    source_ip: str
    auth_method: str
    outcome: str
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> ActivityEntry:
        return cls(
            id=_i(d, "id"),
            time=parse_time(d.get("time")),
            action=_s(d, "action"),
            description=_s(d, "description"),
            target=_s(d, "target"),
            source_ip=_s(d, "source_ip"),
            auth_method=_s(d, "auth_method"),
            outcome=_s(d, "outcome"),
            raw=dict(d),
        )


@dataclass(frozen=True)
class ActivityPage:
    """One page (up to 50 entries) of the activity log, newest first."""

    entries: Tuple[ActivityEntry, ...]

    @property
    def next_before(self) -> Optional[Tuple[str, int]]:
        """``(before_ts, before_id)`` for the next page, or ``None`` when this
        page was not full (so there is nothing older)."""
        if len(self.entries) < 50:
            return None
        last = self.entries[-1]
        return (str(last.raw.get("time", "")), last.id)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> ActivityPage:
        return cls(entries=tuple(ActivityEntry.from_dict(e) for e in _list(d.get("entries")) if isinstance(e, Mapping)))


@dataclass(frozen=True)
class Account:
    """Your profile, limits and permissions."""

    username: str
    email: str
    timezone: str
    email_verified: bool
    totp_enabled: bool
    email_2fa_enabled: bool
    machine_limit: int
    event_limit: int
    event_limit_monthly: bool
    grant_raise: bool
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> Account:
        return cls(
            username=_s(d, "username"),
            email=_s(d, "email"),
            timezone=_s(d, "timezone"),
            email_verified=_b(d, "email_verified"),
            totp_enabled=_b(d, "totp_enabled"),
            email_2fa_enabled=_b(d, "email_2fa_enabled"),
            machine_limit=_i(d, "machine_limit"),
            event_limit=_i(d, "event_limit", -1),
            event_limit_monthly=_b(d, "event_limit_monthly"),
            grant_raise=_b(d, "grant_raise"),
            raw=dict(d),
        )


@dataclass(frozen=True)
class APIKeyInfo:
    """A description of the account's API key. The key itself is never
    returned: only a fingerprint of it is stored."""

    exists: bool
    key_prefix: str = ""
    scope: str = ""
    created_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    last_ip: str = ""

    @property
    def read_only(self) -> bool:
        return self.scope == "read_only"

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> APIKeyInfo:
        return cls(
            exists=_b(d, "exists"),
            key_prefix=_s(d, "key_prefix"),
            scope=_s(d, "scope"),
            created_at=parse_time(d.get("created_at")),
            expires_at=parse_time(d.get("expires_at")),
            last_used_at=parse_time(d.get("last_used_at")),
            last_ip=_s(d, "last_ip"),
        )


@dataclass(frozen=True)
class OnboardingState:
    """How far the account is in setting up es-python."""

    has_plan: bool
    has_python: bool
    machines_total: int
    machines_installed: int
    machines_pending: int
    sources_on: bool
    ran: bool
    events_total: int
    selftest_seen: bool
    next_step: str
    empty_reason: str
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> OnboardingState:
        return cls(
            has_plan=_b(d, "has_plan"),
            has_python=_b(d, "has_python"),
            machines_total=_i(d, "machines_total"),
            machines_installed=_i(d, "machines_installed"),
            machines_pending=_i(d, "machines_pending"),
            sources_on=_b(d, "sources_on"),
            ran=_b(d, "ran"),
            events_total=_i(d, "events_total"),
            selftest_seen=_b(d, "selftest_seen"),
            next_step=_s(d, "next_step"),
            empty_reason=_s(d, "empty_reason"),
            raw=dict(d),
        )
