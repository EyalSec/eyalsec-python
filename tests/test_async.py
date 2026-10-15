from __future__ import annotations

import json
from typing import Callable

import httpx
import pytest

import eyalsec

from .conftest import KEY, FakeAPI, event_row

pytestmark = pytest.mark.anyio

MakeAsync = Callable[[], eyalsec.AsyncEyalSec]


async def test_async_iter_events(api: FakeAPI, make_async: MakeAsync) -> None:
    pages = {
        None: {"events": [event_row(1)], "next_cursor": "a"},
        "a": {"events": [], "next_cursor": "b"},
        "b": {"events": [event_row(2)], "next_cursor": ""},
    }
    api.add(
        "POST",
        "/api/get_all_events_with_count/",
        lambda r: httpx.Response(200, json=pages[json.loads(r.content).get("cursor")]),
    )
    async with make_async() as client:
        ids = [e.id async for e in client.iter_events(view="python")]
    assert ids == [1, 2]
    assert api.requests[0].headers["X-API-Key"] == KEY


async def test_async_errors_and_retry(api: FakeAPI, make_async: MakeAsync) -> None:
    answers = [httpx.Response(429, json={"error": "slow"}, headers={"Retry-After": "1"}), httpx.Response(200, json={})]
    api.add("GET", "/api/account/", lambda r: answers.pop(0))
    api.add("GET", "/api/event/9", httpx.Response(404, text="not found", headers={"content-type": "text/plain"}))
    async with make_async() as client:
        assert (await client.get_account()).username == ""
        with pytest.raises(eyalsec.NotFoundError):
            await client.get_event(9)


async def test_async_writes(api: FakeAPI, make_async: MakeAsync) -> None:
    api.add("POST", "/api/event_labels/", (201, {"id": 2, "name": "fp", "color": "green"}))
    api.add("DELETE", "/api/event_labels/2/", (204, None))
    async with make_async() as client:
        label = await client.create_label("fp", "green")
        assert label == eyalsec.Label(2, "fp", "green")
        assert await client.delete_label(2) is None


async def test_async_runs_and_activity(api: FakeAPI, make_async: MakeAsync) -> None:
    api.add("GET", "/api/runs/", (200, {"runs": [{"run_uid": "r"}], "next_before": ""}))
    api.add("GET", "/api/activity/", (200, {"entries": [{"id": 1, "time": "2026-07-01T00:00:00Z"}]}))
    async with make_async() as client:
        assert [r.run_uid async for r in client.iter_runs()] == ["r"]
        assert [a.id async for a in client.iter_activity()] == [1]
