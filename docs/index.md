# eyalsec

`eyalsec` is the Python client for the [EyalSec API](https://eyalsec.com/docs/api). It reads your security events, machines and runs, and manages your rules, filters, labels and settings, with typed records, a synchronous and an `asyncio` client, paging that follows the cursor for you, and one exception class per kind of error.

```python
import eyalsec

client = eyalsec.EyalSec()  # reads EYALSEC_API_KEY

for event in client.iter_events(severity=["critical", "high"], from_date="2026-10-01"):
    print(event.created_at, event.severity, event.where, event.machine_name)
```

!!! note "This package is the API client, not the runtime"
    `pip install eyalsec` gives you this library. It is not es-python, the EyalSec Python runtime, and importing it adds no security checks to your program. The runtime is installed from your EyalSec dashboard: see the [Quick start](https://eyalsec.com/docs/quick-start) in the EyalSec user guide.

## What you can do with it

- **Report** on what EyalSec found: this week's critical events by machine, the runs behind them, an export for your ticketing system.
- **Gate a pipeline**: install es-python on a CI runner and fail the job when a run reaches a new finding at the severity you choose.
- **Triage in bulk**: label, annotate and filter events from a script.
- **Keep configuration in code**: rules, filters, taint sources, rule templates, the unique-event definition and the outbound connections policy.
- **Provision machines**: add a machine and fetch its one-time install command from your provisioning tooling.

## What EyalSec does

EyalSec follows untrusted data (requests, files, environment variables and more) through your running program and reports when it reaches a risky operation: a SQL query, a shell command, deserialization, a file path. Each event names the operation, the line of code, the value it received and where the untrusted part came from. You run your existing app through es-python, unchanged, and the events arrive on your dashboard. This library reads and manages them.

No account yet? [Book a live demo](https://eyalsec.com/contact) and we will set one up with you. Pricing is at [eyalsec.com/pricing](https://eyalsec.com/pricing).

## Where next

- [Quick start](quickstart.md): install, key, first call.
- [Events and paging](events.md): filters, cursors, runs, export and the map.
- [Errors and retries](errors.md): what each exception means.
- [Reference](reference/client.md): every method and record.
