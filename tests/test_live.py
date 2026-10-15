"""Optional checks against a real EyalSec account.

    EYALSEC_LIVE=1 EYALSEC_API_KEY=es2_... pytest tests/test_live.py

runs a read-only pass. Add EYALSEC_LIVE_WRITES=1 (and a full-access key) to
also create, change and delete a label, a filter, a rule, a saved search, a
rule template and a machine, cleaning each one up again. Point EYALSEC_URL at
a test account, not one you depend on.
"""

from __future__ import annotations

import os
import uuid

import pytest

import eyalsec

live = pytest.mark.skipif(os.environ.get("EYALSEC_LIVE") != "1", reason="set EYALSEC_LIVE=1 to run")
writes = pytest.mark.skipif(os.environ.get("EYALSEC_LIVE_WRITES") != "1", reason="set EYALSEC_LIVE_WRITES=1 to run")


@pytest.fixture(scope="module")
def client() -> eyalsec.EyalSec:
    with eyalsec.EyalSec() as c:
        yield c


@live
def test_read_only_pass(client: eyalsec.EyalSec) -> None:
    account = client.get_account()
    assert account.username
    assert client.get_api_key_info().exists
    machines = client.list_machines()
    assert all(m.public_id for m in machines)
    page = client.query_events()
    assert page.event_limit != 0 or page.events == ()
    events = list(client.iter_events(max_pages=5))
    if events:
        detail = client.get_event(events[0].id)
        assert isinstance(detail.trace, str)
    sev = client.query_events(sort="severity")
    assert isinstance(sev.events, tuple)
    list(client.iter_runs(max_pages=2))
    client.get_event_stats()
    client.get_event_count("python")
    assert "python" in client.get_event_view_counts()
    assert set(client.get_event_visibility_counts()) >= {"live", "suppressed"}
    client.list_event_names()
    client.list_saved_searches()
    client.list_filters()
    client.list_rules()
    assert client.get_taint()
    client.get_event_uniqueness("python")
    client.list_rule_templates()
    client.list_labels()
    client.get_onboarding_state()
    assert client.list_activity().entries
    assert client.list_supported_os_types()
    assert client.list_supported_python_versions().default
    export = client.export_events("json", from_date="2026-01-01")
    assert export.lstrip().startswith((b"{", b"["))
    client.get_event_map()
    with pytest.raises(eyalsec.NotFoundError):
        client.get_event(2**62)


@live
@writes
def test_write_pass(client: eyalsec.EyalSec) -> None:
    tag = "sdk-" + uuid.uuid4().hex[:8]

    label = client.create_label(tag, "cyan")
    try:
        with pytest.raises(eyalsec.ConflictError):
            client.create_label(tag)
        client.update_label(label.id, tag + "-x", "green")
        assert any(lbl.name == tag + "-x" and lbl.color == "green" for lbl in client.list_labels())
        events = client.query_events().events
        if events:
            eid = events[0].id
            client.attach_label(eid, label.id)
            client.set_note(eid, "checked by the eyalsec client tests")
            assert client.get_event(eid).comment == "checked by the eyalsec client tests"
            assert client.query_events(labels=[label.id]).events
            client.delete_note(eid)
            client.detach_label(eid, label.id)
    finally:
        client.delete_label(label.id)

    f = client.create_filter("^" + tag + "$", "blacklist", label=tag)
    try:
        assert client.update_filter(f.id, enabled=False).enabled is False
    finally:
        client.delete_filter(f.id)

    rule = client.create_rule(event_pattern=tag, mode=eyalsec.RuleMode.HIDE, label=tag)
    try:
        assert client.update_rule(rule.id, enabled=False).enabled is False
        assert any(r.id == rule.id for r in client.list_rules())
    finally:
        client.delete_rule(rule.id)

    searches = client.save_search(tag, "view=python&sev=critical")
    sid = next(s.id for s in searches if s.name == tag)
    client.delete_saved_search(sid)

    tpl = client.create_rule_template(tag, [eyalsec.TemplateItem("any", tag, 1)])
    try:
        client.update_rule_template(tpl.id, tag, [eyalsec.TemplateItem("any", tag + "2", 1)])
        res = client.apply_rule_template(tpl.id)
        assert res.added == 1
        again = client.apply_rule_template(tpl.id)
        assert again.added == 0 and again.skipped_duplicate == 1
    finally:
        client.delete_rule_template(tpl.id)
        for r in client.list_rules():
            if r.event_pattern == tag + "2":
                client.delete_rule(r.id)

    m = client.add_machine(tag)
    try:
        assert m.public_id and m.status == "created"
        client.rename_machine(m.public_id, tag + "-r")
        cmd = client.get_install_command(m.public_id, attested=True)
        assert cmd.secret and cmd.script_path.endswith("/install.sh")
        client.set_taint("stdin", "on", machine=m.public_id)
        assert client.get_taint(m.public_id)["stdin"] == "on"
        client.set_event_uniqueness("python", ["source", "trace"], machine=m.public_id)
        assert client.get_event_uniqueness("python", machine=m.public_id).axes == ("source", "trace")
        client.set_event_uniqueness("python", None, machine=m.public_id)
        assert client.get_event_uniqueness("python", machine=m.public_id).inherited
    finally:
        client.delete_machine(m.public_id)
    assert all(x.public_id != m.public_id for x in client.list_machines())

    blocked = client.block_client("192.0.2.77", reason=tag, hours=1)
    try:
        assert any(b.id == blocked.id for b in client.list_blocked_clients())
    finally:
        client.unblock_client(blocked.id)
