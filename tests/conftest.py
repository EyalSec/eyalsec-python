from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx
import pytest

import eyalsec

KEY = "es2_TESTKEYdoNotUse000000000000000000000000000"


class FakeAPI:
    """A tiny stand-in for the EyalSec API. Routes map (method, path) to a
    callable or a fixed (status, body) answer; every request is recorded."""

    def __init__(self) -> None:
        self.routes: Dict[Tuple[str, str], Any] = {}
        self.requests: List[httpx.Request] = []

    def add(self, method: str, path: str, answer: Any) -> None:
        self.routes[(method, path)] = answer

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        answer = self.routes.get((request.method, request.url.path))
        if answer is None:
            return httpx.Response(404, text="<html>no such page</html>", headers={"content-type": "text/html"})
        if callable(answer):
            answer = answer(request)
        if isinstance(answer, httpx.Response):
            return answer
        status, body = answer
        if body is None:
            return httpx.Response(status)
        return httpx.Response(status, json=body)

    def last(self) -> httpx.Request:
        return self.requests[-1]

    def last_json(self) -> Any:
        return json.loads(self.last().content)

    def last_form(self) -> Dict[str, str]:
        from urllib.parse import parse_qsl

        return dict(parse_qsl(self.last().content.decode()))


@pytest.fixture
def api() -> FakeAPI:
    return FakeAPI()


@pytest.fixture
def client(api: FakeAPI, monkeypatch: pytest.MonkeyPatch) -> eyalsec.EyalSec:
    monkeypatch.setattr("time.sleep", lambda s: None)
    c = eyalsec.EyalSec(KEY, base_url="https://eyalsec.test", transport=httpx.MockTransport(api.handler))
    return c


@pytest.fixture
def make_async(api: FakeAPI, monkeypatch: pytest.MonkeyPatch) -> Callable[[], eyalsec.AsyncEyalSec]:
    async def no_sleep(_: float) -> None:
        return None

    monkeypatch.setattr("asyncio.sleep", no_sleep)

    def make(base_url: Optional[str] = "https://eyalsec.test") -> eyalsec.AsyncEyalSec:
        return eyalsec.AsyncEyalSec(KEY, base_url=base_url, transport=httpx.MockTransport(api.handler))

    return make


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def event_row(i: int, **over: Any) -> List[Any]:
    row: List[Any] = [
        "2026-07-05T12:00:00.123456789Z",
        "os system",
        f"'value {i}'",
        3,
        "web-01",
        "high",
        "python",
        i,
        "",
        "",
        False,
        "This value was not sanitized.",
        [{"label": "command injection", "sev": "critical"}],
        [{"id": 1, "name": "triage", "color": "amber"}],
        False,
        "",
        "socket",
    ]
    for k, v in over.items():
        row[eyalsec._models.EVENT_ROW_FIELDS.index(k)] = v
    return row
