# Events and paging

## One page

[`query_events`][eyalsec.EyalSec.query_events] returns one page of up to 100 events, newest first, as an [`EventPage`][eyalsec._models.EventPage]. Every filter matches a control on the dashboard's events page, and every one is optional.

```python
page = client.query_events(
    view="python",  # or "browser"; omitted means every product you have
    severity=["critical", "high"],
    from_date="2026-10-01",  # str, date or datetime
    machine="web-01",  # display name, exact match
    blacklist_repr="^healthcheck",  # regex on the sink label
    sort="severity",  # or "newest" (the default)
)
for event in page.events:
    print(event.id, event.severity, event.where, event.str_repr)
```

Each [`Event`][eyalsec._models.Event] carries the fields of the API's event row by name: `where` is the sink label, `str_repr` the value that reached it, `impact` its impact classes, `labels` your triage labels, and `id` the number to pass to the other event calls.

## Every page

A short page, or even an empty one, is not the last page: each request examines a bounded slice of your history so no call runs for long, and a selective filter can come back empty while matches wait further back. Keep asking until `next_cursor` is empty. [`iter_events`][eyalsec.EyalSec.iter_events] does exactly that:

```python
for event in client.iter_events(tags=["sqli"], bucket="all"):
    ...
```

Pass `max_pages` to stop early. To page by hand, send `page.next_cursor` back as `cursor` with the same filters, and keep the same `sort`: a cursor from one order is refused by the other.

## One event in full

The list leaves out the large fields. [`get_event`][eyalsec.EyalSec.get_event] returns them:

```python
detail = client.get_event(event.id)
print(detail.trace)  # the stack trace at the sink
print(detail.origin)  # where the data came in
print(detail.sink_code)  # source lines around the sink, when the machine sends them
for run in detail.runs:  # the program invocations that produced it
    print(run.cmdline, run.count)
```

An id from another account raises [`NotFoundError`][eyalsec._errors.NotFoundError], exactly like one that does not exist.

## Runs

A run is one invocation of one monitored program.

```python
for run in client.iter_runs(machine="web-01", q="manage.py"):
    print(run.run_uid, run.cmdline, run.events, run.occurrences)

# Only what one run produced (each event's count is then that run's share).
for event in client.iter_events(view="python", run=run.run_uid):
    ...
```

## Counts, statistics and names

```python
client.get_event_stats()  # the dashboard summary
client.get_event_count("python")  # toward this month's quota for es-python
client.get_event_view_counts()  # {"python": 1204, "browser": 38}
client.get_event_visibility_counts()  # {"live": ..., "suppressed": ...}
client.list_event_names()  # distinct sink labels, for building filters
```

## Export and the map

```python
data = client.export_events("csv", view="python", from_date="2026-10-01")
open("findings.csv", "wb").write(data)
```

An export stops at 50,000 rows and says so (a final `TRUNCATED` row in CSV, `"truncated": true` in JSON).

[`get_event_map`][eyalsec.EyalSec.get_event_map] returns the es-python events as a graph of sources, files and sinks, the same one the dashboard's Map layout draws:

```python
graph = client.get_event_map(from_date="2026-10-01")
for link in graph["links"]:
    print(link["source"], link["file"], "->", link["sink"], link["events"])
```

## Saved searches

```python
client.save_search("prod criticals", "machine=web-01&sev=critical", view="python")
for search in client.list_saved_searches("python"):
    print(search.id, search.name, search.query)
```
