from __future__ import annotations

import inspect
import re
import subprocess
import sys
from datetime import date, datetime, timezone
from pathlib import Path

import httpx
import pytest

import eyalsec
from eyalsec import _base

from .conftest import KEY, FakeAPI, event_row

ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- configuration


def test_missing_key_is_a_configuration_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("EYALSEC_API_KEY", raising=False)
    c = eyalsec.EyalSec(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    with pytest.raises(eyalsec.ConfigurationError, match="Settings > API access"):
        c.get_account()


def test_key_and_url_from_environment(monkeypatch: pytest.MonkeyPatch, api: FakeAPI) -> None:
    monkeypatch.setenv("EYALSEC_API_KEY", " es2_fromenv ")
    monkeypatch.setenv("EYALSEC_URL", "https://custom.example/")
    api.add("GET", "/api/account/", (200, {"username": "alice"}))
    c = eyalsec.EyalSec(transport=httpx.MockTransport(api.handler))
    assert c.base_url == "https://custom.example"
    assert c.get_account().username == "alice"
    assert api.last().headers["X-API-Key"] == "es2_fromenv"
    assert api.last().url.host == "custom.example"


def test_default_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("EYALSEC_URL", raising=False)
    assert eyalsec.EyalSec("k").base_url == "https://eyalsec.com"


@pytest.mark.parametrize("url", ["http://eyalsec.com", "ftp://x", "eyalsec.com", "https://"])
def test_insecure_or_bad_base_url_refused(url: str) -> None:
    with pytest.raises(eyalsec.ConfigurationError):
        eyalsec.EyalSec("k", base_url=url)


def test_plain_http_allowed_for_localhost() -> None:
    assert eyalsec.EyalSec("k", base_url="http://localhost:8080/").base_url == "http://localhost:8080"


def test_headers_and_user_agent(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add("GET", "/api/get_all_machines/", (200, {"machines": []}))
    client.list_machines()
    req = api.last()
    assert req.headers["X-API-Key"] == KEY
    assert req.headers["User-Agent"].startswith(f"eyalsec-python/{eyalsec.__version__} ")
    assert req.headers["Accept"] == "application/json"


def test_public_endpoints_send_no_key(api: FakeAPI) -> None:
    api.add("GET", "/api/supported_python_versions/", (200, {"versions": ["3.12", "3.13"], "default": "3.13"}))
    api.add(
        "GET",
        "/api/supported_os_types/",
        (200, {"distros": [{"id": "ubuntu_24_04", "label": "Ubuntu 24.04 LTS", "archs": ["x86_64", "aarch64"]}]}),
    )
    c = eyalsec.EyalSec("", base_url="https://eyalsec.test", transport=httpx.MockTransport(api.handler))
    v = c.list_supported_python_versions("ubuntu_24_04_x86_64")
    assert v.versions == ("3.12", "3.13") and v.default == "3.13"
    assert api.last().url.params["os"] == "ubuntu_24_04_x86_64"
    assert "X-API-Key" not in api.last().headers
    distros = c.list_supported_os_types()
    assert distros[0].os_types() == ["ubuntu_24_04_x86_64", "ubuntu_24_04_aarch64"]


def test_context_manager_closes(api: FakeAPI) -> None:
    with eyalsec.EyalSec("k", base_url="https://eyalsec.test", transport=httpx.MockTransport(api.handler)) as c:
        pass
    assert c._http.is_closed


def test_own_http_client_is_not_closed(api: FakeAPI) -> None:
    http = httpx.Client(transport=httpx.MockTransport(api.handler))
    with eyalsec.EyalSec("k", base_url="https://eyalsec.test", http_client=http):
        pass
    assert not http.is_closed
    http.close()


# --------------------------------------------------------------------------- events


def test_event_row_parsing() -> None:
    row = event_row(7) + ["future-1", "future-2"]
    e = eyalsec.Event.from_row(row)
    assert e.id == 7
    assert e.created_at == datetime(2026, 7, 5, 12, 0, 0, 123456, tzinfo=timezone.utc)
    assert e.where == "os system" and e.severity == "high" and e.agent_kind == "python"
    assert e.impact == (eyalsec.Impact("command injection", "critical"),)
    assert e.labels[0].name == "triage"
    assert e.taint_source == "socket"
    assert e.extra == ("future-1", "future-2")


def test_short_event_row_from_older_server() -> None:
    e = eyalsec.Event.from_row(event_row(1)[:15])
    assert e.extension == "" and e.taint_source == "" and e.extra == ()


def test_query_events_body(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add(
        "POST",
        "/api/get_all_events_with_count/",
        (
            200,
            {
                "events": [event_row(1)],
                "next_cursor": "c2",
                "scanned": 10,
                "exhausted": False,
                "oldest_examined": "2026-07-05T12:00:00Z",
                "event_limit": 5000,
                "event_limit_monthly": True,
            },
        ),
    )
    page = client.query_events(
        view="python",
        from_date=date(2026, 6, 1),
        to_date="2026-06-30",
        severity="critical, high",
        sources=["socket"],
        labels=[3],
        blacklist_repr="^healthcheck$",
        run="9f2c1d4ab8e0472c93ad5f6178be20c4",
        sort="severity",
    )
    body = api.last_json()
    assert api.last().headers["content-type"] == "application/json"
    assert body == {
        "view": "python",
        "sort": "severity",
        "from": "2026-06-01",
        "to": "2026-06-30",
        "severity": ["critical", "high"],
        "sources": ["socket"],
        "labels": [3],
        "blacklist_repr": "^healthcheck$",
        "advanced": {
            "match": "all",
            "conditions": [{"field": "run", "op": "is", "value": "9f2c1d4ab8e0472c93ad5f6178be20c4"}],
        },
    }
    assert page.has_more and page.next_cursor == "c2"
    assert page.events[0].id == 1
    assert page.event_limit == 5000 and page.hidden_by is None


def test_run_with_advanced_any_is_refused() -> None:
    with pytest.raises(ValueError):
        _base.event_filters(advanced={"match": "any", "conditions": []}, run="abc")


def test_run_appends_to_advanced_without_mutating_input() -> None:
    adv = {"match": "all", "conditions": [{"field": "sink", "op": "contains", "value": "sql"}]}
    body = _base.event_filters(advanced=adv, run="r1")
    assert len(body["advanced"]["conditions"]) == 2
    assert len(adv["conditions"]) == 1


def test_iter_events_follows_cursor_past_empty_pages(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    pages = {
        None: {"events": [event_row(1), event_row(2)], "next_cursor": "a"},
        "a": {"events": [], "next_cursor": "b"},  # empty page, NOT the end
        "b": {"events": [event_row(3)], "next_cursor": ""},
    }
    seen = []

    def answer(req: httpx.Request) -> httpx.Response:
        import json

        body = json.loads(req.content)
        seen.append(body)
        return httpx.Response(200, json=pages[body.get("cursor")])

    api.add("POST", "/api/get_all_events_with_count/", answer)
    ids = [e.id for e in client.iter_events(severity=["high"])]
    assert ids == [1, 2, 3]
    assert [b.get("cursor") for b in seen] == [None, "a", "b"]
    assert all(b["severity"] == ["high"] for b in seen)


def test_iter_events_max_pages(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add("POST", "/api/get_all_events_with_count/", (200, {"events": [event_row(1)], "next_cursor": "same-next"}))
    assert len(list(client.iter_events(max_pages=1))) == 1
    # A server handing back the same cursor forever does not loop forever.
    assert len(list(client.iter_events())) == 2


def test_hidden_by(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add(
        "POST",
        "/api/get_all_events_with_count/",
        (200, {"events": [], "next_cursor": "", "exhausted": True, "hidden_by": {"id": 4, "label": "hide all"}}),
    )
    page = client.query_events()
    assert page.hidden_by == eyalsec.HiddenBy(4, "hide all")
    assert not page.has_more


def test_get_event_detail(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add(
        "GET",
        "/api/event/90210",
        (
            200,
            {
                "trace": "Traceback",
                "origin": "{}",
                "repr_created": "<str>",
                "source_code": "",
                "sink_code": "",
                "detail": "/srv/app.py",
                "comment": "fp?",
                "rule_source": "socket",
                "extension": {"id": "", "name": "", "version": "", "label": ""},
                "runs": [
                    {
                        "run_uid": "9f2c",
                        "cmdline": "es-python app.py",
                        "env": "",
                        "count": 12,
                        "first_seen": "2026-09-17T08:12:03Z",
                        "last_seen": "2026-09-17T09:40:51Z",
                    }
                ],
            },
        ),
    )
    d = client.get_event(90210)
    assert d.trace == "Traceback" and d.comment == "fp?" and d.rule_source == "socket"
    assert d.runs[0].count == 12 and d.runs[0].first_seen is not None


def test_event_id_must_be_an_integer(client: eyalsec.EyalSec) -> None:
    with pytest.raises(ValueError):
        client.get_event("1/../../account")  # type: ignore[arg-type]


def test_iter_runs(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    def answer(req: httpx.Request) -> httpx.Response:
        before = req.url.params.get("before")
        if before is None:
            return httpx.Response(200, json={"runs": [{"run_uid": "r1", "events": 7}], "next_before": "x"})
        return httpx.Response(200, json={"runs": [{"run_uid": "r2"}], "next_before": ""})

    api.add("GET", "/api/runs/", answer)
    runs = list(client.iter_runs(machine="web-01", limit=1))
    assert [r.run_uid for r in runs] == ["r1", "r2"]
    assert runs[0].events == 7
    assert api.requests[0].url.params["machine"] == "web-01"
    assert api.requests[0].url.params["limit"] == "1"


def test_counts_and_stats(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add("GET", "/api/event_view_counts/", (200, {"python": 3, "browser": 0}))
    api.add("GET", "/api/event_visibility_counts/", (200, {"live": 1, "suppressed": 2}))
    api.add(
        "GET",
        "/api/event_count/",
        (200, {"count": 4, "view": "python", "event_limit": -1, "event_limit_monthly": False}),
    )
    api.add("GET", "/api/get_event_stats/", (200, {"total_hits": 9, "top_events": [{"where": "x", "count": 1}]}))
    assert client.get_event_view_counts(bucket="all") == {"python": 3, "browser": 0}
    assert api.last().url.params["bucket"] == "all"
    assert client.get_event_visibility_counts() == {"live": 1, "suppressed": 2}
    c = client.get_event_count("python")
    assert c.count == 4 and c.event_limit == -1
    s = client.get_event_stats()
    assert s.total_hits == 9 and s.first_detection is None and s.top_events[0]["where"] == "x"


def test_export_returns_bytes(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add(
        "POST",
        "/api/events_export",
        lambda r: httpx.Response(200, content=b"id,created_at\n1,x\n", headers={"content-type": "text/csv"}),
    )
    out = client.export_events("csv", view="browser", severity=["critical"])
    assert out.startswith(b"id,created_at")
    assert api.last().url.params["format"] == "csv"
    assert api.last_json() == {"view": "browser", "severity": ["critical"]}


def test_event_map_forces_python_view(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add("POST", "/api/event_map/", (200, {"events": 0, "sources": []}))
    client.get_event_map(sink="os system", from_date="2026-07-01")
    assert api.last_json() == {"view": "python", "from": "2026-07-01"}
    assert api.last().url.params["sink"] == "os system"


def test_saved_searches(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add(
        "POST",
        "/api/event_searches/",
        (201, {"searches": [{"id": 3, "name": "mine", "view": "browser", "query": "view=browser"}]}),
    )
    api.add("DELETE", "/api/event_searches/3", (204, None))
    out = client.save_search("mine", "view=browser", view="browser")
    assert out[0].id == 3
    assert client.delete_saved_search(3) is None


# --------------------------------------------------------------------------- machines and CI


def test_list_machines(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    row = [
        "2026-07-01T00:00:00Z",
        "web-01",
        "installed",
        "3f6c1a52",
        "ubuntu_24_04_x86_64",
        "bc0ef13-a",
        "bc0ef13-b",
        "3.13",
        False,
        False,
        False,
        False,
        "python",
    ]
    api.add("GET", "/api/get_all_machines/", (200, {"machines": [row]}))
    (m,) = client.list_machines()
    assert m.public_id == "3f6c1a52" and m.machine_name == "web-01" and m.python_version == "3.13"
    assert m.update_available


def test_add_machine_sends_form_fields(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add(
        "POST",
        "/api/add_new_machine/",
        (200, {"Name": "web-01", "OsType": "auto", "Status": "created", "PublicID": "p1", "AgentKind": "python"}),
    )
    m = client.add_machine("web-01")
    assert api.last().headers["content-type"] == "application/x-www-form-urlencoded"
    assert api.last_form() == {"machine_name": "web-01"}
    assert m.public_id == "p1" and m.os_type == "auto"


def test_install_command_requires_explicit_attestation(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add(
        "POST",
        "/api/get_eyalsec_install_script_data/",
        (
            200,
            {
                "secret": "s3cr3t",
                "script_path": "https://eyalsec.test/install.sh",
                "os_type": "auto",
                "expires_in": 600,
            },
        ),
    )
    with pytest.raises(TypeError):
        client.get_install_command("p1")  # type: ignore[call-arg]
    cmd = client.get_install_command("p1", attested=True)
    assert api.last_json() == {"public_id": "p1", "attested": True}
    assert cmd.expires_in == 600
    assert "s3cr3t" not in repr(cmd)


def test_ci_install_and_findings(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add(
        "POST",
        "/api/ci/install/",
        (200, {"machine_name": "ci-x", "created": True, "secret": "s", "server_time": "2026-10-07T12:00:00Z"}),
    )
    api.add(
        "GET",
        "/api/ci/findings/",
        (
            200,
            {
                "machine": "ci-x",
                "findings": 1,
                "total": 2,
                "by_severity": {"critical": 1, "high": 0},
                "events": [{"id": 5, "severity": "critical", "where": "os system", "new": True}],
            },
        ),
    )
    inst = client.ci_install("ci-x", attested=True, distro="ubuntu_24_04", arch="x86_64")
    assert api.last_form() == {"machine_name": "ci-x", "attested": "true", "distro": "ubuntu_24_04", "arch": "x86_64"}
    assert inst.created
    f = client.ci_findings("ci-x", inst.server_time, min_severity="critical")
    assert api.last().url.params["since"] == "2026-10-07T12:00:00Z"
    assert f.events[0].new and f.by_severity["critical"] == 1
    client.ci_findings("ci-x", 1760000000)
    assert api.last().url.params["since"] == "1760000000"
    client.ci_findings("ci-x", datetime(2026, 10, 7, 12, tzinfo=timezone.utc))
    assert api.last().url.params["since"] == "2026-10-07T12:00:00Z"


# --------------------------------------------------------------------------- rules, filters, templates, labels


def test_rules_capitalized_fields(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    rule = {
        "ID": 12,
        "Source": "any",
        "EventPattern": ".*eval.*",
        "Mode": 3,
        "Action": "raise",
        "Polarity": "whitelist",
        "Label": "block eval",
        "Enabled": True,
        "sanitize_scope": "any",
        "match_on": [],
    }
    api.add("GET", "/api/machine_rules/", (200, {"rules": [rule]}))
    api.add("POST", "/api/machine_rules/create/", (201, rule))
    (r,) = client.list_rules()
    assert api.last().url.params["machine"] == ""
    assert r.id == 12 and r.mode == eyalsec.RuleMode.RAISE and r.event_pattern == ".*eval.*" and r.enabled
    client.create_rule(event_pattern="noise", mode=eyalsec.RuleMode.HIDE, label="hide noise")
    assert api.last_json() == {"machine": "", "event_pattern": "noise", "mode": 1, "label": "hide noise"}


def test_update_sends_only_given_fields(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add("PATCH", "/api/filters/7/update/", (200, {"id": 7, "pattern": "x", "mode": "blacklist", "enabled": False}))
    f = client.update_filter(7, enabled=False)
    assert api.last_json() == {"enabled": False}
    assert not f.enabled


def test_templates(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add(
        "GET",
        "/api/rule_templates/",
        (
            200,
            {
                "templates": [
                    {
                        "id": 3,
                        "owner": "eyalsec",
                        "name": "basics",
                        "items": [{"source": "socket", "event_pattern": "exec", "mode": 2}],
                        "category": "protect",
                    }
                ],
                "categories": [{"key": "protect", "name": "Block attacks", "blurb": "b"}],
            },
        ),
    )
    api.add("POST", "/api/rule_templates/3/apply/", (200, {"added": 5, "skipped_raise": 2, "skipped_duplicate": 1}))
    api.add("POST", "/api/rule_templates/create/", (201, {"id": 12, "owner": "me", "name": "mine", "items": []}))
    tl = client.list_rule_templates()
    assert tl.templates[0].items[0].sanitize_scope == "any"
    assert tl.categories[0].key == "protect"
    res = client.apply_rule_template(3, machine="p1")
    assert api.last_json() == {"machine": "p1"}
    assert res.added == 5 and res.skipped_raise == 2
    client.create_rule_template("mine", [eyalsec.TemplateItem("socket", "exec", 2), {"source": "any", "mode": 1}])
    assert api.last_json()["items"] == [
        {"source": "socket", "event_pattern": "exec", "mode": 2, "sanitize_scope": "any"},
        {"source": "any", "mode": 1},
    ]


def test_labels_and_notes(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add("POST", "/api/event_labels/", (201, {"id": 1, "name": "triage", "color": "amber"}))
    api.add("POST", "/api/event/5/labels/", (204, None))
    api.add("DELETE", "/api/event/5/labels/1/", (204, None))
    api.add("PUT", "/api/event/5/comment/", (204, None))
    label = client.create_label("triage", "amber")
    client.attach_label(5, label.id)
    assert api.last_json() == {"label_id": 1}
    client.detach_label(5, 1)
    client.set_note(5, "looks fine")
    assert api.last_json() == {"body": "looks fine"}


def test_taint_and_uniqueness(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add("PUT", "/api/machine_taint/", (204, None))
    api.add("PUT", "/api/event_uniqueness/", (204, None))
    client.set_taint("socket", "on", machine="p1")
    assert api.last_json() == {"machine": "p1", "source": "socket", "state": "on"}
    client.set_event_uniqueness("python", None)
    assert api.last_json() == {"agent_kind": "python", "machine": ""}
    client.set_event_uniqueness("python", [])
    assert api.last_json() == {"agent_kind": "python", "machine": "", "axes": []}


def test_set_egress_sends_null_to_inherit(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add("PUT", "/api/egress/", (200, {"machine": ""}))
    client.set_egress([{"action": "deny", "target": "@metadata"}], default="deny")
    assert api.last_json() == {
        "machine": "",
        "mode": None,
        "default": "deny",
        "on_violation": None,
        "rules": [{"action": "deny", "target": "@metadata"}],
    }


# --------------------------------------------------------------------------- account


def test_activity_pagination(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    full = [{"id": 100 - i, "time": f"2026-07-16T06:{i:02d}:00Z", "action": "api.request"} for i in range(50)]

    def answer(req: httpx.Request) -> httpx.Response:
        if "before_id" not in req.url.params:
            return httpx.Response(200, json={"entries": full})
        return httpx.Response(200, json={"entries": [{"id": 1, "time": "2026-07-01T00:00:00Z"}]})

    api.add("GET", "/api/activity/", answer)
    entries = list(client.iter_activity())
    assert len(entries) == 51
    assert api.requests[1].url.params["before_id"] == "51"
    assert api.requests[1].url.params["before_ts"] == "2026-07-16T06:49:00Z"


def test_generate_api_key_switches_client_key(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add("POST", "/api/account/apikey/generate", (200, {"api_key": "es2_NEW", "note": "shown once"}))
    api.add("GET", "/api/account/", (200, {"username": "a"}))
    key = client.generate_api_key(password="pw", expires=date(2027, 1, 1), read_only=True)
    assert key == "es2_NEW"
    assert api.last_form() == {"password": "pw", "expires": "2027-01-01", "read_only": "1"}
    client.get_account()
    assert api.last().headers["X-API-Key"] == "es2_NEW"


def test_selftest_nonce_checked(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    with pytest.raises(ValueError):
        client.get_selftest_status("../account")
    api.add("GET", "/api/selftest/5fdc376114ee72259c9249b36f64ceee", (200, {"received": True}))
    assert client.get_selftest_status("5FDC376114EE72259C9249B36F64CEEE")["received"] is True


# --------------------------------------------------------------------------- errors and retries


@pytest.mark.parametrize(
    "status,cls",
    [
        (400, eyalsec.BadRequestError),
        (401, eyalsec.AuthenticationError),
        (403, eyalsec.PermissionDeniedError),
        (404, eyalsec.NotFoundError),
        (409, eyalsec.ConflictError),
        (422, eyalsec.UnprocessableEntityError),
        (500, eyalsec.InternalServerError),
        (418, eyalsec.APIError),
    ],
)
def test_status_maps_to_exception(client: eyalsec.EyalSec, api: FakeAPI, status: int, cls: type) -> None:
    api.add("GET", "/api/account/", (status, {"error": "nope"}))
    with pytest.raises(cls) as info:
        client.get_account()
    err = info.value
    assert isinstance(err, eyalsec.APIError) and isinstance(err, eyalsec.EyalSecError)
    assert err.status == status and err.message == "nope"
    assert err.path == "/api/account/" and err.method == "GET"
    assert "nope" in str(err)


def test_plain_text_error_body(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add("GET", "/api/event/1", httpx.Response(404, text="not found\n", headers={"content-type": "text/plain"}))
    with pytest.raises(eyalsec.NotFoundError) as info:
        client.get_event(1)
    assert info.value.message == "not found"
    assert not info.value.unavailable


def test_html_404_means_endpoint_unavailable(client: eyalsec.EyalSec) -> None:
    with pytest.raises(eyalsec.NotFoundError) as info:
        client.list_routes()
    assert info.value.unavailable and info.value.message == ""
    assert "does not offer" in str(info.value)


def test_redirect_is_reported(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add("GET", "/api/account/", httpx.Response(302, headers={"location": "/login/"}))
    with pytest.raises(eyalsec.UnexpectedResponseError, match="/login/"):
        client.get_account()


def test_non_json_success_is_reported(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add("GET", "/api/account/", httpx.Response(200, text="<html>", headers={"content-type": "text/html"}))
    with pytest.raises(eyalsec.UnexpectedResponseError):
        client.get_account()


def test_429_is_retried_after_retry_after(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    answers = [
        httpx.Response(429, json={"error": "slow down"}, headers={"Retry-After": "2"}),
        httpx.Response(200, json={"machines": []}),
    ]
    api.add("GET", "/api/get_all_machines/", lambda r: answers.pop(0))
    assert client.list_machines() == []
    assert len(api.requests) == 2


def test_429_gives_up_after_max_retries(api: FakeAPI, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("time.sleep", lambda s: None)
    api.add("GET", "/api/get_all_machines/", httpx.Response(429, text="slow", headers={"Retry-After": "1"}))
    c = eyalsec.EyalSec("k", base_url="https://eyalsec.test", max_retries=1, transport=httpx.MockTransport(api.handler))
    with pytest.raises(eyalsec.RateLimitError) as info:
        c.list_machines()
    assert info.value.retry_after == 1.0
    assert len(api.requests) == 2


def test_long_retry_after_is_not_waited_out(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add("GET", "/api/get_all_machines/", httpx.Response(429, json={"error": "x"}, headers={"Retry-After": "900"}))
    with pytest.raises(eyalsec.RateLimitError):
        client.list_machines()
    assert len(api.requests) == 1


def test_account_lockout_429_is_not_retried(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add("POST", "/api/account/apikey/revoke", httpx.Response(429, json={"error": "locked"}))
    with pytest.raises(eyalsec.RateLimitError):
        client.revoke_api_key(password="pw")
    assert len(api.requests) == 1


def test_503_retried_for_reads_not_for_writes(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    answers = [httpx.Response(503), httpx.Response(200, json={"labels": []})]
    api.add("GET", "/api/event_labels/", lambda r: answers.pop(0))
    assert client.list_labels() == []
    api.requests.clear()
    api.add("POST", "/api/event_labels/", httpx.Response(503))
    with pytest.raises(eyalsec.InternalServerError):
        client.create_label("x")
    assert len(api.requests) == 1


def test_events_query_post_is_retried_as_a_read(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    answers = [httpx.Response(502), httpx.Response(200, json={"events": [], "next_cursor": ""})]
    api.add("POST", "/api/get_all_events_with_count/", lambda r: answers.pop(0))
    assert client.query_events().events == ()


def test_connection_errors(api: FakeAPI, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("time.sleep", lambda s: None)
    calls = []

    def boom(req: httpx.Request) -> httpx.Response:
        calls.append(req.method)
        raise httpx.ConnectError("refused", request=req)

    c = eyalsec.EyalSec("k", base_url="https://eyalsec.test", transport=httpx.MockTransport(boom))
    with pytest.raises(eyalsec.APIConnectionError):
        c.list_machines()
    assert calls == ["GET", "GET", "GET"]
    calls.clear()
    with pytest.raises(eyalsec.APIConnectionError):
        c.add_machine("x")
    assert calls == ["POST"]


def test_timeout_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("time.sleep", lambda s: None)

    def slow(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=req)

    c = eyalsec.EyalSec("k", base_url="https://eyalsec.test", max_retries=0, transport=httpx.MockTransport(slow))
    with pytest.raises(eyalsec.APITimeoutError):
        c.get_account()


def test_retry_after_http_date() -> None:
    assert _base.parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0
    assert _base.parse_retry_after("3") == 3.0
    assert _base.parse_retry_after("soon") is None


def test_204_returns_none(client: eyalsec.EyalSec, api: FakeAPI) -> None:
    api.add("DELETE", "/api/filters/7/delete/", (204, None))
    assert client.delete_filter(7) is None


# --------------------------------------------------------------------------- package hygiene


def test_sync_and_async_have_the_same_methods() -> None:
    def public(cls: type) -> dict:
        return {n: inspect.signature(m) for n, m in vars(cls).items() if callable(m) and not n.startswith("_")}

    sync, asyn = public(eyalsec.EyalSec), public(eyalsec.AsyncEyalSec)
    asyn["close"] = asyn.pop("aclose")
    assert sync.keys() == asyn.keys()
    for name in sync:
        assert list(sync[name].parameters) == list(asyn[name].parameters), name


def test_sync_client_is_generated_from_async() -> None:
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "unasync.py"), "--check"], capture_output=True)
    assert result.returncode == 0, result.stderr.decode()


def test_versions_agree() -> None:
    text = (ROOT / "pyproject.toml").read_text()
    m = re.search(r'^version = "([^"]+)"', text, re.M)
    assert m and m.group(1) == eyalsec.__version__


def test_no_console_script_shadows_the_runtime() -> None:
    text = (ROOT / "pyproject.toml").read_text()
    assert "[project.scripts]" not in text
    assert not re.search(r'^\s*"?es-python"?\s*=', text, re.M)


def test_documented_endpoints_are_covered() -> None:
    """Every key-callable endpoint in the API reference has a method."""
    source = (ROOT / "src" / "eyalsec" / "_async_client.py").read_text()
    paths = [
        "/api/get_all_events_with_count/",
        "/api/event/{",
        "/api/runs/",
        "/api/get_event_stats/",
        "/api/event_count/",
        "/api/event_view_counts/",
        "/api/event_visibility_counts/",
        "/api/events_export",
        "/api/event_map/",
        "/api/event_names/",
        "/api/event_searches/",
        "/api/get_all_machines/",
        "/api/add_new_machine/",
        "/api/set_machine_os/",
        "/api/rename_machine/",
        "/api/delete_machine/",
        "/api/get_eyalsec_install_script_data/",
        "/api/get_uninstall_script_data/",
        "/api/supported_os_types/",
        "/api/supported_python_versions/",
        "/api/ci/install/",
        "/api/ci/findings/",
        "/api/filters/",
        "/api/machine_rules/",
        "/api/machine_taint/",
        "/api/web_protection/",
        "/api/web_protection/blocklist/",
        "/api/web_protection/routes/",
        "/api/event_uniqueness/",
        "/api/egress/",
        "/api/rule_templates/",
        "/api/rule_templates/snapshot/",
        "/api/event_labels/",
        "/labels/",
        "/comment/",
        "/api/activity/",
        "/api/account/",
        "/api/account/timezone",
        "/api/account/email",
        "/api/account/password",
        "/api/account/delete",
        "/api/account/2fa/setup",
        "/api/account/2fa/enable",
        "/api/account/2fa/disable",
        "/api/account/2fa/backup/regenerate",
        "/api/account/2fa/email/enable",
        "/api/account/2fa/email/disable",
        "/api/account/apikey",
        "/api/account/apikey/generate",
        "/api/account/apikey/revoke",
        "/api/onboarding_state/",
        "/api/selftest/",
    ]
    missing = [p for p in paths if p not in source]
    assert not missing


def test_module_main(capsys: pytest.CaptureFixture[str]) -> None:
    from eyalsec.__main__ import main

    assert main([]) == 0
    out = capsys.readouterr().out
    assert "not es-python" in out and eyalsec.__version__ in out


def test_importing_issues_no_warning() -> None:
    result = subprocess.run(
        [sys.executable, "-W", "error", "-c", "import eyalsec"],
        capture_output=True,
        env={"PYTHONPATH": str(ROOT / "src")},
    )
    assert result.returncode == 0, result.stderr.decode()
