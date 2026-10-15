# Errors and retries

Every error the client raises on purpose is an [`EyalSecError`][eyalsec._errors.EyalSecError].

| What happened | Exception |
|---|---|
| No API key, or an `http://` address that is not `localhost` | `ConfigurationError` |
| No answer: DNS, TLS, refused or dropped connection | `APIConnectionError` |
| No answer in time | `APITimeoutError` |
| 400 | `BadRequestError` |
| 401: missing, wrong, revoked or expired key | `AuthenticationError` |
| 403: read-only key writing, product not on the account, wrong password | `PermissionDeniedError` |
| 404: not found, or not yours | `NotFoundError` |
| 409: machine limit reached, name taken | `ConflictError` |
| 422: a field missing or invalid | `UnprocessableEntityError` |
| 429: rate limit, or sign-in lockout | `RateLimitError` |
| 5xx | `InternalServerError` |
| A redirect, or a body that is not JSON | `UnexpectedResponseError` |

Every [`APIError`][eyalsec._errors.APIError] carries `status`, `message` (the server's short message), `method`, `path` and, for a 429, `retry_after`.

```python
try:
    client.add_machine("web-03")
except eyalsec.ConflictError as e:
    print("At the machine limit:", e.message)
except eyalsec.PermissionDeniedError:
    print("This key is read-only, or es-python is not on this account.")
```

A `NotFoundError` with `unavailable=True` means the address answered with its generic "no such page" instead of an API error: that EyalSec address does not offer the endpoint (for example one still running an older release).

## Retries

- A **429** is retried after the server's `Retry-After`, up to `max_retries` times (default 2). A wait longer than a minute is not slept through: the error is raised so you can decide. A 429 on a password-checked account call is never retried, since it can be a sign-in lockout.
- A **read** (and the events query, export and map, which are reads sent as POST) is retried after a dropped connection, a timeout, or a 502, 503 or 504.
- A **write** is never retried after a dropped connection, because there is no way to know whether it was applied.

```python
client = eyalsec.EyalSec(max_retries=5, timeout=60)
```

The API allows 300 requests a minute per account, and 120 a minute per address for the events calls together. See [rate limits](https://eyalsec.com/docs/api#rate-limits).
