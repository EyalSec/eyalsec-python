# eyalsec: the Python client for the EyalSec API

[![PyPI](https://img.shields.io/pypi/v/eyalsec.svg)](https://pypi.org/project/eyalsec/)
[![Python versions](https://img.shields.io/pypi/pyversions/eyalsec.svg)](https://pypi.org/project/eyalsec/)
[![CI](https://github.com/EyalSec/eyalsec-python/actions/workflows/ci.yml/badge.svg)](https://github.com/EyalSec/eyalsec-python/actions/workflows/ci.yml)
[![Docs](https://readthedocs.org/projects/eyalsec/badge/?version=latest)](https://eyalsec.readthedocs.io)

Work with your EyalSec account from Python: pull this week's critical events into a report, fail a pipeline on a new finding, label and annotate events in bulk, keep rules and filters in code, or add a machine from your provisioning script. Everything the [EyalSec API](https://eyalsec.com/docs/api) offers is a typed method here, in a synchronous and an `asyncio` flavour, with paging, retries and clear errors handled for you.

```python
import eyalsec

client = eyalsec.EyalSec()  # reads EYALSEC_API_KEY

for event in client.iter_events(severity=["critical", "high"], from_date="2026-10-01"):
    print(event.created_at, event.severity, event.where, event.machine_name)
```

> **This package is the API client, not the runtime.** `pip install eyalsec` gives you this library. It is not es-python, the EyalSec Python runtime, and importing it adds no security checks to your program. The runtime is installed from your EyalSec dashboard: see the [Quick start](https://eyalsec.com/docs/quick-start).

## What EyalSec does

EyalSec follows untrusted data (requests, files, environment variables and more) through your running program and reports when it reaches a risky operation: a SQL query, a shell command, deserialization, a file path. Each event names the operation, the line of code, the value it received and where the untrusted part came from. You run your existing app through es-python, unchanged, and the events arrive on your dashboard. This library reads and manages them.

## Install

```bash
pip install eyalsec
```

Python 3.9 or newer. The only dependency is [`httpx`](https://www.python-httpx.org/).

## Get a key

Create an API key on your dashboard under **Settings > API access** and put it in `EYALSEC_API_KEY`. A **read-only key** can call every read, and it is the one to use for reports and dashboards; scripts that change things need a full key. See [API keys](https://eyalsec.com/docs/api-keys).

```bash
export EYALSEC_API_KEY=es2_your_key
python -m eyalsec --check    # calls the API once and prints the account it reached
```

No account yet? [Book a live demo](https://eyalsec.com/contact) and we will set one up with you. Pricing is at [eyalsec.com/pricing](https://eyalsec.com/pricing).

## Examples

### Events

```python
page = client.query_events(view="python", sort="severity")  # one page, up to 100
for event in page.events:
    print(event.id, event.severity, event.where, event.str_repr)

detail = client.get_event(page.events[0].id)  # the large fields
print(detail.trace)
print(detail.source_code, detail.sink_code)

# Every event, following the cursor for you (including past empty pages).
critical = list(client.iter_events(severity="critical", machine="web-01"))

# What one run of a program produced.
run = next(client.iter_runs(q="manage.py"))
for event in client.iter_events(view="python", run=run.run_uid):
    print(event.where, event.count)

csv_bytes = client.export_events("csv", view="python", from_date="2026-10-01")
```

### Triage

```python
label = client.create_label("needs review", "amber")
for event in client.iter_events(tags=["sqli"], bucket="live"):
    client.attach_label(event.id, label.id)
    client.set_note(event.id, "Queued for the Thursday review.")
```

### Rules and filters as code

```python
from eyalsec import RuleMode

client.create_rule(event_pattern="^healthcheck", mode=RuleMode.HIDE, label="health checks")
client.create_filter("^socket-recv$", "blacklist", label="noise")
client.set_taint("socket", "on")  # your account default
client.apply_rule_template(template_id=3, machine=None)  # None means your global rules
```

### Machines and CI

```python
machine = client.add_machine("web-02")  # build detected at install time
command = client.get_install_command(machine.public_id, attested=True)
print(command.script_path, command.expires_in)  # the secret is single-use

install = client.ci_install("ci-myrepo", attested=True, distro="ubuntu_24_04", arch="x86_64")
# ... run your tests under es-python ...
result = client.ci_findings("ci-myrepo", since=install.server_time, min_severity="high")
if result.findings:
    raise SystemExit(f"{result.findings} findings at high or above: {result.url}")
```

`attested=True` is your confirmation that you are authorized to monitor that machine, the same box the dashboard asks you to tick.

### asyncio

```python
import asyncio
import eyalsec


async def main() -> None:
    async with eyalsec.AsyncEyalSec() as client:
        async for event in client.iter_events(severity=["critical"]):
            print(event.id, event.where)


asyncio.run(main())
```

`AsyncEyalSec` has exactly the same methods as `EyalSec`.

## Errors

Every error the client raises is an `eyalsec.EyalSecError`. An error status becomes a subclass you can catch by meaning:

| Status | Exception |
|---|---|
| 400 | `BadRequestError` |
| 401 | `AuthenticationError` (missing, wrong, revoked or expired key) |
| 403 | `PermissionDeniedError` (for example a read-only key trying to write) |
| 404 | `NotFoundError` (also for things on another account, so their existence is never confirmed) |
| 409 | `ConflictError` (for example the machine limit is reached) |
| 422 | `UnprocessableEntityError` |
| 429 | `RateLimitError`, with `retry_after` |
| 5xx | `InternalServerError` |

Each carries `status`, `message`, `method` and `path`. A request that got no answer raises `APIConnectionError` (or `APITimeoutError`).

The client retries a rate-limited request after the server's `Retry-After` (up to `max_retries`, default 2), and retries reads after a dropped connection or a 502, 503 or 504. Writes are never retried after a dropped connection, because there is no way to know whether they applied. The API's [rate limits](https://eyalsec.com/docs/api#rate-limits) are 300 requests a minute per account.

## Configuration

| Argument | Environment | Default |
|---|---|---|
| `api_key` | `EYALSEC_API_KEY` | none (required for everything but the two public lists) |
| `base_url` | `EYALSEC_URL` | `https://eyalsec.com` |
| `timeout` | | 30 seconds |
| `max_retries` | | 2 |
| `http_client` | | your own `httpx.Client` / `httpx.AsyncClient`, for proxies or custom TLS |

The key is sent only to `base_url`, only over HTTPS (plain `http://` is accepted for `localhost` alone), and never appears in a `repr`.

## Documentation

- This library: [eyalsec.readthedocs.io](https://eyalsec.readthedocs.io)
- The API it calls: [eyalsec.com/docs/api](https://eyalsec.com/docs/api)
- EyalSec user guide: [eyalsec.com/docs](https://eyalsec.com/docs)

Related: [eyalsec-cli](https://github.com/EyalSec/eyalsec-cli) for the terminal, [eyalsec-mcp](https://github.com/EyalSec/eyalsec-mcp) for AI assistants, and [es-python-action](https://github.com/EyalSec/es-python-action) for GitHub Actions.

## Development

```bash
git clone https://github.com/EyalSec/eyalsec-python && cd eyalsec-python
python -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'
pytest
```

`src/eyalsec/_client.py` is generated from `_async_client.py`: edit the async file and run `python scripts/unasync.py`. The tests run against a fake API; `EYALSEC_LIVE=1` adds a read-only pass against your own account (see `tests/test_live.py`).

## Help

Questions and bug reports are welcome in [issues](https://github.com/EyalSec/eyalsec-python/issues), or write to support@eyalsec.com. Please send security reports to security@eyalsec.com rather than a public issue.

## License

MIT. See [LICENSE](LICENSE). The license covers this client library; your EyalSec account is governed by the [EyalSec terms](https://eyalsec.com/legal/terms).
