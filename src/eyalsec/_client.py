"""The synchronous client, :class:`EyalSec`.

GENERATED from ``_async_client.py`` by ``scripts/unasync.py``. Do not edit
this file by hand: edit ``_async_client.py`` and run the script again.
"""

from __future__ import annotations

import time
from types import TracebackType
from typing import Any, Iterator, Dict, List, Mapping, Optional, Sequence, Tuple, Type, Union

import httpx

from . import _base
from ._base import DateLike, StrList, form, machine_param, params
from ._errors import APIConnectionError, APITimeoutError
from ._models import (
    Account,
    ActivityEntry,
    ActivityPage,
    APIKeyInfo,
    BlockedClient,
    CIFindings,
    CIInstall,
    Distro,
    Event,
    EventCount,
    EventDetail,
    EventPage,
    EventStats,
    EventUniqueness,
    Filter,
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
    TemplateItem,
)

__all__ = ["EyalSec"]

TemplateItemLike = Union[TemplateItem, Mapping[str, Any]]


def _items(items: Sequence[TemplateItemLike]) -> List[Dict[str, Any]]:
    return [i.to_dict() if isinstance(i, TemplateItem) else dict(i) for i in items]


def _since(value: Union[DateLike, int, float]) -> str:
    if isinstance(value, bool):
        raise TypeError("since must be a date, a datetime, an RFC 3339 string or Unix seconds")
    if isinstance(value, (int, float)):
        return str(int(value))
    return params(since=value)["since"]


class EyalSec:
    """Client for the EyalSec API.

    Args:
        api_key: Your API key (it starts with ``es2_``). Defaults to the
            ``EYALSEC_API_KEY`` environment variable. Create one on your
            dashboard under **Settings > API access**; a read-only key can
            call every read.
        base_url: Your EyalSec address. Defaults to ``EYALSEC_URL``, then to
            ``https://eyalsec.com``. Must be ``https://`` (plain ``http://``
            is accepted only for ``localhost``).
        timeout: Seconds to wait for each request.
        max_retries: How many times to retry a request that hit a rate limit
            (honouring ``Retry-After``), or a read that hit a dropped
            connection or a 502/503/504. Writes are never retried after a
            dropped connection, because it is unknown whether they applied.
        http_client: An ``httpx.Client`` to send requests through, for
            proxies or custom TLS. The client does not close one you pass.
        transport: An ``httpx`` transport, mainly for tests.

    Use it as a context manager, or call :meth:`close` when done::

        with EyalSec() as client:
            for event in client.iter_events(severity=["critical", "high"]):
                print(event.id, event.where)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        *,
        base_url: Optional[str] = None,
        timeout: float = _base.DEFAULT_TIMEOUT,
        max_retries: int = _base.DEFAULT_MAX_RETRIES,
        http_client: Optional[httpx.Client] = None,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> None:
        self.api_key = _base.resolve_api_key(api_key)
        self.base_url = _base.normalize_base_url(base_url)
        self.max_retries = max(0, int(max_retries))
        self._owns_http = http_client is None
        self._http = http_client or httpx.Client(
            transport=transport,
            timeout=timeout,
            follow_redirects=False,
            headers={"User-Agent": _base.user_agent(), "Accept": "application/json"},
        )

    def __repr__(self) -> str:
        return f"{type(self).__name__}(base_url={self.base_url!r})"

    def __enter__(self) -> EyalSec:
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.close()

    def close(self) -> None:
        """Close the connection pool (unless you passed your own ``http_client``)."""
        if self._owns_http:
            self._http.close()

    # ------------------------------------------------------------------ transport

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: Optional[Mapping[str, str]] = None,
        json: Any = None,
        data: Optional[Mapping[str, str]] = None,
        public: bool = False,
        raw: bool = False,
    ) -> Any:
        headers: Dict[str, str] = {}
        if not public:
            if not self.api_key:
                raise _base.missing_key_error()
            headers["X-API-Key"] = self.api_key
        if json is not None:
            headers["Content-Type"] = "application/json"
        idempotent = method in ("GET", "HEAD", "PUT", "DELETE") or (method == "POST" and path in _base.IDEMPOTENT_POSTS)
        # A 429 on a password-checked account call can be a sign-in lockout
        # that lasts minutes: report it rather than retrying into it.
        retry_429 = not (method == "POST" and path.startswith("/api/account/"))
        url = self.base_url + path
        attempt = 0
        while True:
            attempt += 1
            try:
                resp = self._http.request(
                    method, url, params=dict(query) if query else None, json=json, data=data, headers=headers
                )
            except httpx.TimeoutException as exc:
                if idempotent and attempt <= self.max_retries:
                    time.sleep(_base.retry_wait(attempt, None))
                    continue
                raise APITimeoutError(f"{method} {path} timed out talking to {self.base_url}") from exc
            except httpx.TransportError as exc:
                if idempotent and attempt <= self.max_retries:
                    time.sleep(_base.retry_wait(attempt, None))
                    continue
                raise APIConnectionError(
                    f"{method} {path}: could not reach {self.base_url} ({type(exc).__name__}: {exc})"
                ) from exc
            status = resp.status_code
            if attempt <= self.max_retries and (
                (status == 429 and retry_429) or (idempotent and status in (502, 503, 504))
            ):
                wait = _base.parse_retry_after(resp.headers.get("retry-after"))
                if wait is None or wait <= _base.MAX_RETRY_WAIT:
                    time.sleep(_base.retry_wait(attempt, wait))
                    continue
            _base.raise_for_response(resp, method, path)
            if raw:
                return resp.content
            return _base.decode_json(resp, method, path)

    def _get_dict(
        self, path: str, query: Optional[Mapping[str, str]] = None, *, public: bool = False
    ) -> Dict[str, Any]:
        return _base.as_dict(self._request("GET", path, query=query, public=public), "GET", path)

    # ------------------------------------------------------------------ events

    def query_events(
        self,
        *,
        cursor: Optional[str] = None,
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
    ) -> EventPage:
        """Return one page (up to 100) of your events, newest first by default.

        Every filter is optional and matches a control on the events page:
        ``view`` (``"python"`` or ``"browser"``), ``bucket`` (``"live"``,
        ``"suppressed"`` or ``"all"``), ``sort`` (``"newest"`` or
        ``"severity"``), ``from_date``/``to_date``, ``machine`` (display
        name), ``severity``, ``sources``, ``tags`` (impact classes),
        ``labels`` (label ids), ``whitelist_repr``/``blacklist_repr`` (regexes
        on the sink label), ``xss_only``, ``scope`` and ``advanced`` (the
        condition builder). ``run`` keeps only what one run produced.
        ``extra`` is merged into the body as is, for fields this version does
        not know.

        A short or empty page is not the last page: pass ``page.next_cursor``
        back as ``cursor`` (with the same filters) until it is empty, or use
        :meth:`iter_events`.
        """
        body = _base.event_filters(
            view=view,
            bucket=bucket,
            sort=sort,
            from_date=from_date,
            to_date=to_date,
            machine=machine,
            severity=severity,
            sources=sources,
            tags=tags,
            labels=labels,
            whitelist_repr=whitelist_repr,
            blacklist_repr=blacklist_repr,
            xss_only=xss_only,
            scope=scope,
            advanced=advanced,
            run=run,
            extra=extra,
        )
        if cursor:
            body["cursor"] = cursor
        path = "/api/get_all_events_with_count/"
        return EventPage.from_dict(_base.as_dict(self._request("POST", path, json=body), "POST", path))

    def iter_events(
        self,
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
        max_pages: Optional[int] = None,
    ) -> Iterator[Event]:
        """Yield every event matching the filters, following the cursor.

        Takes the same filters as :meth:`query_events`. It keeps asking until
        the cursor comes back empty, including past empty pages (each request
        examines a bounded slice of history, so a selective filter can return
        an empty page that still has matches further back). ``max_pages``
        stops after that many requests.
        """
        cursor: Optional[str] = None
        pages = 0
        while True:
            page = self.query_events(
                cursor=cursor,
                view=view,
                bucket=bucket,
                sort=sort,
                from_date=from_date,
                to_date=to_date,
                machine=machine,
                severity=severity,
                sources=sources,
                tags=tags,
                labels=labels,
                whitelist_repr=whitelist_repr,
                blacklist_repr=blacklist_repr,
                xss_only=xss_only,
                scope=scope,
                advanced=advanced,
                run=run,
                extra=extra,
            )
            pages += 1
            for event in page.events:
                yield event
            if not page.next_cursor or page.next_cursor == cursor:
                return
            if max_pages is not None and pages >= max_pages:
                return
            cursor = page.next_cursor

    def get_event(self, event_id: int) -> EventDetail:
        """Return one event's stack trace, origin, source listings, your note
        and the runs that produced it. ``event_id`` is :attr:`Event.id`."""
        path = f"/api/event/{int(event_id)}"
        return EventDetail.from_dict(self._get_dict(path))

    def list_runs(
        self,
        *,
        machine: Optional[str] = None,
        q: Optional[str] = None,
        before: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> RunPage:
        """Return one page of the runs behind your events, newest first.

        ``machine`` is a display name, ``q`` a piece of the command line,
        ``limit`` 1 to 200. Pass ``page.next_before`` as ``before`` for the
        next page, or use :meth:`iter_runs`.
        """
        return RunPage.from_dict(
            self._get_dict("/api/runs/", params(machine=machine, q=q, before=before or None, limit=limit))
        )

    def iter_runs(
        self,
        *,
        machine: Optional[str] = None,
        q: Optional[str] = None,
        limit: Optional[int] = None,
        max_pages: Optional[int] = None,
    ) -> Iterator[Run]:
        """Yield every run, following ``next_before`` until it is empty."""
        before: Optional[str] = None
        pages = 0
        while True:
            page = self.list_runs(machine=machine, q=q, before=before, limit=limit)
            pages += 1
            for run in page.runs:
                yield run
            if not page.next_before or page.next_before == before:
                return
            if max_pages is not None and pages >= max_pages:
                return
            before = page.next_before

    def get_event_stats(self) -> EventStats:
        """Return the summary the dashboard shows: totals, the last hour, day
        and week, top event types, recent events and a 14-day timeline."""
        return EventStats.from_dict(self._get_dict("/api/get_event_stats/"))

    def get_event_count(self, view: Optional[str] = None) -> EventCount:
        """Return how many events count toward your quota period. Pass a
        ``view``: the quota is per product, so that is the number a list is
        capped by. The count may be a few minutes behind."""
        return EventCount.from_dict(self._get_dict("/api/event_count/", params(view=view)))

    def get_event_view_counts(
        self,
        *,
        bucket: Optional[str] = None,
        scope: Optional[str] = None,
        scope_mode: Optional[str] = None,
        scope_empty: Optional[bool] = None,
    ) -> Dict[str, int]:
        """Return how many events each product's list would show, such as
        ``{"python": 1204, "browser": 38}``."""
        d = self._get_dict(
            "/api/event_view_counts/",
            params(bucket=bucket, scope=scope, scope_mode=scope_mode, scope_empty=scope_empty),
        )
        return {str(k): int(v) for k, v in d.items() if isinstance(v, (int, float))}

    def get_event_visibility_counts(self) -> Dict[str, int]:
        """Return ``{"live": ..., "suppressed": ...}``: every stored event is
        in exactly one of the two."""
        d = self._get_dict("/api/event_visibility_counts/")
        return {str(k): int(v) for k, v in d.items() if isinstance(v, (int, float))}

    def export_events(
        self,
        format: str = "csv",
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
    ) -> bytes:
        """Download every event matching the filters as a ``"csv"`` or
        ``"json"`` file and return its bytes.

        An export stops at 50,000 rows and says so: the CSV ends with a row
        beginning ``TRUNCATED`` and the JSON sets ``"truncated": true``.
        """
        body = _base.event_filters(
            view=view,
            bucket=bucket,
            sort=sort,
            from_date=from_date,
            to_date=to_date,
            machine=machine,
            severity=severity,
            sources=sources,
            tags=tags,
            labels=labels,
            whitelist_repr=whitelist_repr,
            blacklist_repr=blacklist_repr,
            xss_only=xss_only,
            scope=scope,
            advanced=advanced,
            run=run,
            extra=extra,
        )
        result: bytes = self._request("POST", "/api/events_export", query={"format": format}, json=body, raw=True)
        return result

    def get_event_map(
        self,
        *,
        source: Optional[str] = None,
        file: Optional[str] = None,
        sink: Optional[str] = None,
        only: Optional[str] = None,
        bucket: Optional[str] = None,
        from_date: Optional[DateLike] = None,
        to_date: Optional[DateLike] = None,
        machine: Optional[str] = None,
        severity: Optional[StrList] = None,
        sources: Optional[StrList] = None,
        tags: Optional[StrList] = None,
        labels: Optional[Sequence[int]] = None,
        whitelist_repr: Optional[str] = None,
        blacklist_repr: Optional[str] = None,
        scope: Optional[Mapping[str, Any]] = None,
        advanced: Optional[Mapping[str, Any]] = None,
        run: Optional[str] = None,
        extra: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return your es-python events as a graph of sources, files and sinks.

        ``source``, ``file`` or ``sink`` focus on one node, and the answer
        then also carries ``focus.events`` (rows in the events-list shape; turn
        them into :class:`Event` with ``Event.from_row``). ``only="focus"``
        returns just that part. The rest of the arguments are the events
        filters; the view is always ``python``.
        """
        body = _base.event_filters(
            view="python",
            bucket=bucket,
            from_date=from_date,
            to_date=to_date,
            machine=machine,
            severity=severity,
            sources=sources,
            tags=tags,
            labels=labels,
            whitelist_repr=whitelist_repr,
            blacklist_repr=blacklist_repr,
            scope=scope,
            advanced=advanced,
            run=run,
            extra=extra,
        )
        path = "/api/event_map/"
        query = params(source=source, file=file, sink=sink, only=only)
        return _base.as_dict(self._request("POST", path, query=query, json=body), "POST", path)

    def list_event_names(self) -> List[str]:
        """Return the distinct sink labels (``where``) across your events."""
        d = self._get_dict("/api/event_names/")
        return [str(n) for n in d.get("names") or []]

    def list_saved_searches(self, view: str = "python") -> List[SavedSearch]:
        """Return your saved searches for one product."""
        d = self._get_dict("/api/event_searches/", params(view=view))
        return [SavedSearch.from_dict(s) for s in d.get("searches") or []]

    def save_search(self, name: str, query: str, *, view: str = "python") -> List[SavedSearch]:
        """Save a named events-page query string (without the leading ``?``).
        Saving the same name again overwrites it. Returns that product's whole
        list, so the new id is in it."""
        path = "/api/event_searches/"
        d = _base.as_dict(
            self._request("POST", path, json={"name": name, "view": view, "query": query}), "POST", path
        )
        return [SavedSearch.from_dict(s) for s in d.get("searches") or []]

    def delete_saved_search(self, search_id: int) -> None:
        """Delete one saved search."""
        self._request("DELETE", f"/api/event_searches/{int(search_id)}")

    # ------------------------------------------------------------------ machines

    def list_machines(self) -> List[Machine]:
        """Return every machine on your account."""
        d = self._get_dict("/api/get_all_machines/")
        return [Machine.from_row(r) for r in d.get("machines") or []]

    def add_machine(
        self,
        machine_name: str,
        *,
        product: Optional[str] = None,
        distro: Optional[str] = None,
        arch: Optional[str] = None,
        python_version: Optional[str] = None,
    ) -> NewMachine:
        """Register a new machine.

        ``product`` is ``"python"`` (the default) or ``"browser"``. For
        es-python, leave ``distro`` and ``arch`` out to have the build detected
        when the install runs, or give both (see
        :meth:`list_supported_os_types`). At your machine limit this raises
        :class:`ConflictError`.
        """
        path = "/api/add_new_machine/"
        data = form(machine_name=machine_name, product=product, distro=distro, arch=arch, python_version=python_version)
        return NewMachine.from_dict(_base.as_dict(self._request("POST", path, data=data), "POST", path))

    def set_machine_os(self, machine_name: str, distro: str, arch: str) -> Dict[str, Any]:
        """Change the distribution and architecture a machine is installed for."""
        path = "/api/set_machine_os/"
        data = form(machine_name=machine_name, distro=distro, arch=arch)
        return _base.as_dict(self._request("POST", path, data=data), "POST", path)

    def rename_machine(self, public_id: str, machine_name: str) -> Dict[str, Any]:
        """Give a machine a new display name (1 to 128 characters)."""
        path = "/api/rename_machine/"
        body = {"public_id": public_id, "machine_name": machine_name}
        return _base.as_dict(self._request("POST", path, json=body), "POST", path)

    def delete_machine(self, public_id: str) -> None:
        """Delete a machine **and every event it reported**. Cannot be undone."""
        self._request("POST", "/api/delete_machine/", json={"public_id": public_id})

    def get_install_command(
        self, public_id: str, *, attested: bool, renew: Optional[bool] = None
    ) -> InstallCommand:
        """Issue a one-time install secret for an es-python machine.

        ``attested=True`` is your confirmation that you are authorized to
        monitor that machine, the same box the dashboard asks you to tick.
        An installed machine is reset for a fresh install first (this is how
        you reinstall); ``renew=True`` instead refuses with
        :class:`ConflictError` once the machine has started installing.
        """
        body: Dict[str, Any] = {"public_id": public_id, "attested": bool(attested)}
        if renew is not None:
            body["renew"] = bool(renew)
        path = "/api/get_eyalsec_install_script_data/"
        return InstallCommand.from_dict(_base.as_dict(self._request("POST", path, json=body), "POST", path))

    def get_uninstall_command(self, public_id: str) -> InstallCommand:
        """Issue a one-time secret for removing es-python from a machine."""
        path = "/api/get_uninstall_script_data/"
        return InstallCommand.from_dict(
            _base.as_dict(self._request("POST", path, json={"public_id": public_id}), "POST", path)
        )

    def list_supported_os_types(self) -> List[Distro]:
        """Return the distributions and architectures es-python installs on.
        Needs no API key."""
        d = self._get_dict("/api/supported_os_types/", public=True)
        return [Distro.from_dict(x) for x in d.get("distros") or []]

    def list_supported_python_versions(self, os_type: Optional[str] = None) -> PythonVersions:
        """Return the Python versions you can pick, and the default. Pass an
        ``os_type`` such as ``"ubuntu_24_04_x86_64"`` to get only the versions
        available for it. Needs no API key."""
        d = self._get_dict("/api/supported_python_versions/", params(os=os_type), public=True)
        return PythonVersions.from_dict(d)

    # ------------------------------------------------------------------ CI

    def ci_install(
        self,
        machine_name: str,
        *,
        attested: bool,
        distro: Optional[str] = None,
        arch: Optional[str] = None,
        python_version: Optional[str] = None,
    ) -> CIInstall:
        """Get a one-time install secret for a CI runner's machine, found by
        name and created the first time (``distro`` and ``arch`` are then
        required). Call it once per pipeline run."""
        path = "/api/ci/install/"
        data = form(
            machine_name=machine_name, attested=attested, distro=distro, arch=arch, python_version=python_version
        )
        return CIInstall.from_dict(_base.as_dict(self._request("POST", path, data=data), "POST", path))

    def ci_findings(
        self,
        machine: str,
        since: Union[DateLike, int, float],
        *,
        min_severity: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> CIFindings:
        """Return what runs on one machine reported since a moment.

        ``since`` is a ``datetime``, an RFC 3339 string or Unix seconds;
        prefer the server's clock (:attr:`CIInstall.server_time`) to the
        runner's. ``min_severity`` defaults to ``"high"`` on the server.
        """
        query = params(machine=machine, min_severity=min_severity, limit=limit)
        query["since"] = _since(since)
        return CIFindings.from_dict(self._get_dict("/api/ci/findings/", query))

    # ------------------------------------------------------------------ filters

    def list_filters(self, engine: Optional[str] = None) -> List[Filter]:
        """Return your event filters, or only those shown on one product's
        Filters page when ``engine`` is given."""
        d = self._get_dict("/api/filters/", params(engine=engine))
        return [Filter.from_dict(f) for f in d.get("filters") or []]

    def create_filter(
        self,
        pattern: str,
        mode: str,
        *,
        target: Optional[str] = None,
        engine: Optional[str] = None,
        label: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> Filter:
        """Add an event filter. ``mode`` is ``"blacklist"`` (hide matches) or
        ``"whitelist"`` (show only matches); ``target`` is ``"where"`` (the
        default), ``"origin"`` or ``"tag"``."""
        body: Dict[str, Any] = {"pattern": pattern, "mode": mode}
        for k, v in (("target", target), ("engine", engine), ("label", label), ("enabled", enabled)):
            if v is not None:
                body[k] = v
        path = "/api/filters/create/"
        return Filter.from_dict(_base.as_dict(self._request("POST", path, json=body), "POST", path))

    def update_filter(
        self,
        filter_id: int,
        *,
        pattern: Optional[str] = None,
        mode: Optional[str] = None,
        target: Optional[str] = None,
        label: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> Filter:
        """Change a filter. Only the fields you pass are sent."""
        body = {
            k: v
            for k, v in (
                ("pattern", pattern),
                ("mode", mode),
                ("target", target),
                ("label", label),
                ("enabled", enabled),
            )
            if v is not None
        }
        path = f"/api/filters/{int(filter_id)}/update/"
        return Filter.from_dict(_base.as_dict(self._request("PATCH", path, json=body), "PATCH", path))

    def delete_filter(self, filter_id: int) -> None:
        """Delete a filter."""
        self._request("DELETE", f"/api/filters/{int(filter_id)}/delete/")

    # ------------------------------------------------------------------ rules

    def list_rules(self, machine: Optional[str] = None) -> List[Rule]:
        """Return the rules in one scope: a machine's ``public_id``, or
        ``None`` for your global rules."""
        d = self._get_dict("/api/machine_rules/", {"machine": machine_param(machine)})
        return [Rule.from_dict(r) for r in d.get("rules") or []]

    def create_rule(
        self,
        *,
        machine: Optional[str] = None,
        event_pattern: Optional[str] = None,
        mode: Optional[int] = None,
        source: Optional[str] = None,
        sanitize_scope: Optional[str] = None,
        label: Optional[str] = None,
        enabled: Optional[bool] = None,
        from_event: Optional[int] = None,
        match_on: Optional[Sequence[str]] = None,
        event_machine: Optional[bool] = None,
    ) -> Rule:
        """Add a rule to a scope (``machine`` is a ``public_id``, or ``None``
        for global).

        ``mode`` is ``1`` Hide, ``2`` Show (the default), ``3`` Raise or ``4``
        Don't send (see :class:`RuleMode`). ``from_event`` makes the rule from
        an event; ``match_on`` and ``event_machine`` refine it. A Raise rule
        needs Raise enabled for your account (:attr:`Account.grant_raise`).
        """
        body: Dict[str, Any] = {"machine": machine_param(machine)}
        for k, v in (
            ("event_pattern", event_pattern),
            ("mode", int(mode) if mode is not None else None),
            ("source", source),
            ("sanitize_scope", sanitize_scope),
            ("label", label),
            ("enabled", enabled),
            ("from_event", int(from_event) if from_event is not None else None),
            ("match_on", list(match_on) if match_on is not None else None),
            ("event_machine", event_machine),
        ):
            if v is not None:
                body[k] = v
        path = "/api/machine_rules/create/"
        return Rule.from_dict(_base.as_dict(self._request("POST", path, json=body), "POST", path))

    def update_rule(
        self,
        rule_id: int,
        *,
        event_pattern: Optional[str] = None,
        mode: Optional[int] = None,
        source: Optional[str] = None,
        sanitize_scope: Optional[str] = None,
        label: Optional[str] = None,
        enabled: Optional[bool] = None,
    ) -> Rule:
        """Change a rule. Only the fields you pass are sent."""
        body = {
            k: v
            for k, v in (
                ("event_pattern", event_pattern),
                ("mode", int(mode) if mode is not None else None),
                ("source", source),
                ("sanitize_scope", sanitize_scope),
                ("label", label),
                ("enabled", enabled),
            )
            if v is not None
        }
        path = f"/api/machine_rules/{int(rule_id)}/update/"
        return Rule.from_dict(_base.as_dict(self._request("PATCH", path, json=body), "PATCH", path))

    def delete_rule(self, rule_id: int) -> None:
        """Delete a rule."""
        self._request("DELETE", f"/api/machine_rules/{int(rule_id)}/delete/")

    # ------------------------------------------------------------------ taint

    def get_taint(self, machine: Optional[str] = None) -> Dict[str, str]:
        """Return every taint setting in one scope, each ``"on"``, ``"off"``
        or ``"unset"`` (inherit)."""
        d = self._get_dict("/api/machine_taint/", {"machine": machine_param(machine)})
        taint = d.get("taint") or {}
        return {str(k): str(v) for k, v in taint.items()}

    def set_taint(self, source: str, state: str, *, machine: Optional[str] = None) -> None:
        """Set one taint setting (such as ``"socket"``) to ``"on"``, ``"off"``
        or ``"unset"`` in one scope. es-python applies it when the program
        next starts."""
        body = {"machine": machine_param(machine), "source": source, "state": state}
        self._request("PUT", "/api/machine_taint/", json=body)

    # ------------------------------------------------------------------ web protection

    def get_web_protection(self, machine: Optional[str] = None) -> Dict[str, Any]:
        """Return the web protection settings stored in one scope
        (``settings``), the values that apply where nothing is stored
        (``inherited``), and ``can_block``."""
        return self._get_dict("/api/web_protection/", {"machine": machine_param(machine)})

    def set_web_protection(self, key: str, value: str, *, machine: Optional[str] = None) -> None:
        """Store one web protection setting, such as ``("rate", "on")``. An
        empty ``value`` clears it."""
        body = {"machine": machine_param(machine), "key": key, "value": value}
        self._request("PUT", "/api/web_protection/", json=body)

    def list_blocked_clients(self) -> List[BlockedClient]:
        """Return your blocked clients, newest first (expired ones left out)."""
        d = self._get_dict("/api/web_protection/blocklist/")
        return [BlockedClient.from_dict(e) for e in d.get("entries") or []]

    def block_client(
        self, address: str, *, reason: Optional[str] = None, hours: Optional[int] = None
    ) -> BlockedClient:
        """Block an address or range. ``hours`` until it expires; ``None``
        or ``0`` for never."""
        body: Dict[str, Any] = {"address": address}
        if reason is not None:
            body["reason"] = reason
        if hours is not None:
            body["hours"] = int(hours)
        path = "/api/web_protection/blocklist/"
        return BlockedClient.from_dict(_base.as_dict(self._request("POST", path, json=body), "POST", path))

    def unblock_client(self, entry_id: int) -> None:
        """Remove one blocklist entry."""
        self._request("DELETE", f"/api/web_protection/blocklist/{int(entry_id)}/")

    def list_routes(self) -> List[Dict[str, Any]]:
        """Return the routes your applications served while route inventory
        is on, with request counts and events per route."""
        d = self._get_dict("/api/web_protection/routes/")
        return [dict(r) for r in d.get("routes") or []]

    # ------------------------------------------------------------------ unique events

    def get_event_uniqueness(
        self, agent_kind: str, *, machine: Optional[str] = None, event: Optional[int] = None
    ) -> EventUniqueness:
        """Return the unique-event definition in force for one product
        (``agent_kind``, such as ``"python"``) and scope."""
        query = {"agent_kind": agent_kind, "machine": machine_param(machine)}
        if event is not None:
            query["event"] = str(int(event))
        return EventUniqueness.from_dict(self._get_dict("/api/event_uniqueness/", query))

    def set_event_uniqueness(
        self, agent_kind: str, axes: Optional[Sequence[str]], *, machine: Optional[str] = None
    ) -> None:
        """Set which fields split events, for one product and scope.

        ``axes`` is any of ``source``, ``detail``, ``trace``, ``machine``,
        ``origin``; ``[]`` keeps only the baseline, and ``None`` removes this
        scope's own setting so it inherits again.
        """
        body: Dict[str, Any] = {"agent_kind": agent_kind, "machine": machine_param(machine)}
        if axes is not None:
            body["axes"] = list(axes)
        self._request("PUT", "/api/event_uniqueness/", json=body)

    # ------------------------------------------------------------------ outbound connections

    def get_egress(self, machine: Optional[str] = None) -> Dict[str, Any]:
        """Return the es-python outbound connections policy for your account,
        or for one machine: what the scope stores, and what is ``effective``."""
        return self._get_dict("/api/egress/", params(machine=machine or None))

    def set_egress(
        self,
        rules: Sequence[Mapping[str, Any]],
        *,
        machine: Optional[str] = None,
        mode: Optional[str] = None,
        default: Optional[str] = None,
        on_violation: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Replace one scope's outbound connections policy and its whole rule
        list. Each rule is ``{"action": "allow"|"deny", "target": ..., "note": ...}``.
        A setting left as ``None`` inherits."""
        body = {
            "machine": machine_param(machine),
            "mode": mode,
            "default": default,
            "on_violation": on_violation,
            "rules": [dict(r) for r in rules],
        }
        path = "/api/egress/"
        return _base.as_dict(self._request("PUT", path, json=body), "PUT", path)

    # ------------------------------------------------------------------ rule templates

    def list_rule_templates(self) -> RuleTemplateList:
        """Return every template you can see (your own and EyalSec's), and
        the categories the Templates page lists them under."""
        return RuleTemplateList.from_dict(self._get_dict("/api/rule_templates/"))

    def create_rule_template(
        self, name: str, items: Sequence[TemplateItemLike], *, description: Optional[str] = None
    ) -> RuleTemplate:
        """Create one of your own templates. Each item is checked as a rule is."""
        body: Dict[str, Any] = {"name": name, "items": _items(items)}
        if description is not None:
            body["description"] = description
        path = "/api/rule_templates/create/"
        return RuleTemplate.from_dict(_base.as_dict(self._request("POST", path, json=body), "POST", path))

    def update_rule_template(
        self,
        template_id: int,
        name: str,
        items: Sequence[TemplateItemLike],
        *,
        description: Optional[str] = None,
    ) -> None:
        """Rename one of your templates and replace its whole rule list."""
        body: Dict[str, Any] = {"name": name, "items": _items(items)}
        if description is not None:
            body["description"] = description
        self._request("PATCH", f"/api/rule_templates/{int(template_id)}/update/", json=body)

    def delete_rule_template(self, template_id: int) -> None:
        """Delete one of your templates. Rules already applied from it stay."""
        self._request("DELETE", f"/api/rule_templates/{int(template_id)}/delete/")

    def apply_rule_template(self, template_id: int, *, machine: Optional[str] = None) -> TemplateApplyResult:
        """Add a template's rules to a scope. Duplicates, and Raise rules when
        Raise is not enabled for you, are skipped and counted."""
        path = f"/api/rule_templates/{int(template_id)}/apply/"
        d = self._request("POST", path, json={"machine": machine_param(machine)})
        return TemplateApplyResult.from_dict(_base.as_dict(d, "POST", path))

    def snapshot_rule_template(
        self, name: str, *, machine: Optional[str] = None, description: Optional[str] = None
    ) -> RuleTemplate:
        """Save the rules currently in a scope as a new template of your own."""
        body: Dict[str, Any] = {"name": name, "machine": machine_param(machine)}
        if description is not None:
            body["description"] = description
        path = "/api/rule_templates/snapshot/"
        return RuleTemplate.from_dict(_base.as_dict(self._request("POST", path, json=body), "POST", path))

    # ------------------------------------------------------------------ labels and notes

    def list_labels(self) -> List[Label]:
        """Return your triage labels."""
        d = self._get_dict("/api/event_labels/")
        return [Label.from_dict(x) for x in d.get("labels") or []]

    def create_label(self, name: str, color: Optional[str] = None) -> Label:
        """Create a label. ``color`` is one of ``amber``, ``cyan``, ``red``,
        ``green``, ``blue``, ``slate``, ``violet``, ``pink``."""
        body: Dict[str, Any] = {"name": name}
        if color is not None:
            body["color"] = color
        path = "/api/event_labels/"
        return Label.from_dict(_base.as_dict(self._request("POST", path, json=body), "POST", path))

    def update_label(self, label_id: int, name: str, color: Optional[str] = None) -> None:
        """Set a label's name and color. Both are written every time, so
        leaving ``color`` out sets it back to amber."""
        body: Dict[str, Any] = {"name": name}
        if color is not None:
            body["color"] = color
        self._request("PATCH", f"/api/event_labels/{int(label_id)}/", json=body)

    def delete_label(self, label_id: int) -> None:
        """Delete a label and remove it from every event."""
        self._request("DELETE", f"/api/event_labels/{int(label_id)}/")

    def attach_label(self, event_id: int, label_id: int) -> None:
        """Put one of your labels on one of your events."""
        self._request("POST", f"/api/event/{int(event_id)}/labels/", json={"label_id": int(label_id)})

    def detach_label(self, event_id: int, label_id: int) -> None:
        """Take one label off one event."""
        self._request("DELETE", f"/api/event/{int(event_id)}/labels/{int(label_id)}/")

    def set_note(self, event_id: int, body: str) -> None:
        """Set your note on an event (at most 4096 bytes), replacing any
        earlier one. Read it back with :meth:`get_event`."""
        self._request("PUT", f"/api/event/{int(event_id)}/comment/", json={"body": body})

    def delete_note(self, event_id: int) -> None:
        """Remove your note from an event."""
        self._request("DELETE", f"/api/event/{int(event_id)}/comment/")

    # ------------------------------------------------------------------ activity

    def list_activity(
        self,
        *,
        action: Optional[str] = None,
        outcome: Optional[str] = None,
        before_ts: Optional[str] = None,
        before_id: Optional[int] = None,
    ) -> ActivityPage:
        """Return one page (up to 50) of your activity log, newest first.
        Entries are kept for 30 days."""
        query = params(action=action, outcome=outcome, before_ts=before_ts, before_id=before_id)
        return ActivityPage.from_dict(self._get_dict("/api/activity/", query))

    def iter_activity(
        self,
        *,
        action: Optional[str] = None,
        outcome: Optional[str] = None,
        max_pages: Optional[int] = None,
    ) -> Iterator[ActivityEntry]:
        """Yield every activity log entry, newest first, page by page."""
        before: Optional[Tuple[str, int]] = None
        pages = 0
        while True:
            page = self.list_activity(
                action=action,
                outcome=outcome,
                before_ts=before[0] if before else None,
                before_id=before[1] if before else None,
            )
            pages += 1
            for entry in page.entries:
                yield entry
            nxt = page.next_before
            if nxt is None or nxt == before:
                return
            if max_pages is not None and pages >= max_pages:
                return
            before = nxt

    # ------------------------------------------------------------------ account

    def get_account(self) -> Account:
        """Return your profile, limits and permissions."""
        return Account.from_dict(self._get_dict("/api/account/"))

    def get_onboarding_state(self) -> OnboardingState:
        """Return how far the account is in setting up es-python."""
        return OnboardingState.from_dict(self._get_dict("/api/onboarding_state/"))

    def set_timezone(self, timezone: str) -> str:
        """Set the time zone dates are shown in (an IANA name, or ``""`` for
        automatic). Returns the stored value."""
        path = "/api/account/timezone"
        d = _base.as_dict(self._request("POST", path, data=form(timezone=timezone)), "POST", path)
        return str(d.get("timezone", ""))

    def change_email(self, email: str, *, password: str, totp: Optional[str] = None) -> Dict[str, Any]:
        """Change (or, with ``""``, remove) your recovery email. A new address
        is applied only when the link sent to it is clicked."""
        path = "/api/account/email"
        data = form(email=email, password=password, totp=totp)
        return _base.as_dict(self._request("POST", path, data=data), "POST", path)

    def change_password(
        self, current_password: str, new_password: str, *, totp: Optional[str] = None
    ) -> Dict[str, Any]:
        """Change your password. **This revokes your API key and every
        session**, including the key this client is using."""
        path = "/api/account/password"
        data = form(current_password=current_password, new_password=new_password, confirm=new_password, totp=totp)
        return _base.as_dict(self._request("POST", path, data=data), "POST", path)

    def delete_account(self, *, password: str, totp: Optional[str] = None) -> None:
        """Delete your account and everything in it. There is no undo."""
        self._request("POST", "/api/account/delete", data=form(password=password, totp=totp))

    def start_totp_setup(self) -> Dict[str, Any]:
        """Start authenticator-app setup: returns a new ``secret`` and
        ``otpauth_url``, held for 10 minutes."""
        return self._get_dict("/api/account/2fa/setup")

    def enable_totp(self, *, password: str, totp: str) -> Dict[str, Any]:
        """Finish authenticator setup with a code from the new secret. The
        answer holds your backup codes, shown only this once."""
        path = "/api/account/2fa/enable"
        return _base.as_dict(self._request("POST", path, data=form(password=password, totp=totp)), "POST", path)

    def disable_totp(self, *, password: str, totp: Optional[str] = None) -> Dict[str, Any]:
        """Turn off the authenticator app. Signs out every session."""
        path = "/api/account/2fa/disable"
        return _base.as_dict(self._request("POST", path, data=form(password=password, totp=totp)), "POST", path)

    def regenerate_backup_codes(self, *, password: str, totp: Optional[str] = None) -> Dict[str, Any]:
        """Replace your backup codes; the old ones stop working."""
        path = "/api/account/2fa/backup/regenerate"
        return _base.as_dict(self._request("POST", path, data=form(password=password, totp=totp)), "POST", path)

    def enable_email_2fa(self, *, password: str, totp: Optional[str] = None) -> Dict[str, Any]:
        """Turn on email sign-in codes (needs a recovery email on file)."""
        path = "/api/account/2fa/email/enable"
        return _base.as_dict(self._request("POST", path, data=form(password=password, totp=totp)), "POST", path)

    def disable_email_2fa(self, *, password: str, totp: Optional[str] = None) -> Dict[str, Any]:
        """Turn off email sign-in codes."""
        path = "/api/account/2fa/email/disable"
        return _base.as_dict(self._request("POST", path, data=form(password=password, totp=totp)), "POST", path)

    def get_api_key_info(self) -> APIKeyInfo:
        """Describe the key on your account: prefix, scope, expiry and last
        use. The key itself is never returned."""
        return APIKeyInfo.from_dict(self._get_dict("/api/account/apikey"))

    def generate_api_key(
        self,
        *,
        password: str,
        totp: Optional[str] = None,
        expires: Optional[DateLike] = None,
        read_only: bool = False,
    ) -> str:
        """Create a new key, which **replaces the current one**, and return it.

        This client switches to the new key, so it keeps working. ``expires``
        is a future date; ``read_only=True`` makes a key that can only read.
        """
        exp = params(expires=expires).get("expires")
        if exp and "T" in exp:
            exp = exp.split("T", 1)[0]
        data = form(password=password, totp=totp, expires=exp, read_only="1" if read_only else None)
        path = "/api/account/apikey/generate"
        d = _base.as_dict(self._request("POST", path, data=data), "POST", path)
        key = str(d.get("api_key", ""))
        if key:
            self.api_key = key
        return key

    def revoke_api_key(self, *, password: str, totp: Optional[str] = None) -> None:
        """Delete your key. If it is the key this client uses, this is the
        last call it can make."""
        self._request("POST", "/api/account/apikey/revoke", data=form(password=password, totp=totp))

    # ------------------------------------------------------------------ self-test

    def get_selftest_status(self, nonce: str) -> Dict[str, Any]:
        """Return whether the ``eyalsec selftest`` run with this 32-character
        hex ``nonce`` reached the dashboard. Needs no API key."""
        nonce = nonce.strip().lower()
        if len(nonce) != 32 or any(c not in "0123456789abcdef" for c in nonce):
            raise ValueError("nonce must be 32 lowercase hexadecimal characters")
        return self._get_dict(f"/api/selftest/{nonce}", public=True)
