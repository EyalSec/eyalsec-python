# asyncio

[`AsyncEyalSec`][eyalsec.AsyncEyalSec] has the same methods as [`EyalSec`][eyalsec.EyalSec]. Await them, and use `async for` with the `iter_*` methods.

```python
import asyncio
import eyalsec


async def main() -> None:
    async with eyalsec.AsyncEyalSec() as client:
        account, machines = await asyncio.gather(client.get_account(), client.list_machines())
        print(account.username, len(machines))

        async for event in client.iter_events(severity="critical"):
            detail = await client.get_event(event.id)
            print(event.where, detail.trace.splitlines()[-1:])


asyncio.run(main())
```

Close the client with `async with` or `await client.aclose()`. To share a connection pool or set a proxy, pass your own `httpx.AsyncClient` as `http_client`; the client then leaves closing it to you.

The API's rate limits apply to concurrent calls as much as to sequential ones, so keep fan-out modest (a few requests at a time).
