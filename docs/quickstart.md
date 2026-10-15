# Quick start

## Install

```bash
pip install eyalsec
```

Python 3.9 or newer. The only dependency is [`httpx`](https://www.python-httpx.org/).

## Create an API key

On your EyalSec dashboard, open **Settings > API access** and generate a key. It starts with `es2_` and is shown once, so copy it then. A **read-only key** can call every read; scripts that change things need a full key. See [API keys](https://eyalsec.com/docs/api-keys) in the user guide.

Put it in the environment:

```bash
export EYALSEC_API_KEY=es2_your_key
```

and check it:

```bash
python -m eyalsec --check
```

which calls the API once and prints the account it reached, the key's scope and the number of machines.

## First calls

```python
import eyalsec

with eyalsec.EyalSec() as client:
    account = client.get_account()
    print(account.username, "may add", account.machine_limit, "machines per product")

    for machine in client.list_machines():
        print(machine.machine_name, machine.status, machine.os_type)

    stats = client.get_event_stats()
    print(stats.total_hits, "hits,", stats.last_24h, "in the last day")
```

You can also pass the key and address directly:

```python
client = eyalsec.EyalSec("es2_your_key", base_url="https://eyalsec.com")
```

`base_url` is your EyalSec address. For the hosted service it is `https://eyalsec.com`, which is the default; set it (or `EYALSEC_URL`) only if your account lives on another domain. It must be `https://`.

## Next

- [Events and paging](events.md)
- [Triage, rules and settings](manage.md)
- [Machines and CI](machines.md)
