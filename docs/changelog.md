# Changelog

## 1.1.1 (2026-10-19)

- README and docs: updated "What EyalSec does". The PyPI classifier is now "Development Status :: 5 - Production/Stable". No code changes.

## 1.1.0 (2026-10-15)

`eyalsec` is now the Python client for the EyalSec API.

- `EyalSec` (sync) and `AsyncEyalSec` (`asyncio`) with a method for every endpoint an API key can call: events, event detail, runs, counts, statistics, export, the events map, saved searches, machines, install and uninstall commands, CI install and findings, filters, machine rules, taint sources, web protection, the unique-event definition, outbound connections, rule templates, labels and notes, the activity log, and account settings.
- Typed, frozen records for what the API returns, built from its fixed-order rows by position, with any newer values kept in `extra` and the original JSON in `raw`.
- `iter_events`, `iter_runs` and `iter_activity` follow the API's paging, including past empty event pages.
- One exception class per kind of error, and retries for rate limits and for reads after a dropped connection.
- `python -m eyalsec --check` calls the API once with `EYALSEC_API_KEY`.
- Importing the package no longer issues a warning. `about()`, the link constants and `EyalSecNoticeWarning` are kept so 1.0 code still runs.
- Licensed under MIT.

## 1.0.0 (2026-10-15)

A pointer package: it explained that the EyalSec Python runtime is installed from the EyalSec dashboard, not from pip.
