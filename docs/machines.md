# Machines and CI

## Machines

```python
for m in client.list_machines():
    flag = " (update available)" if m.update_available else ""
    print(m.public_id, m.machine_name, m.status, m.os_type, m.python_version + flag)
```

`public_id` is the machine's handle in every other call. Its secret is never returned.

### Add one

```python
m = client.add_machine("web-02")  # es-python, build detected on the host at install time
```

or choose the build yourself:

```python
targets = client.list_supported_os_types()  # needs no key
versions = client.list_supported_python_versions("ubuntu_24_04_x86_64")
m = client.add_machine("web-02", distro="ubuntu_24_04", arch="x86_64", python_version=versions.default)
```

At your machine limit this raises [`ConflictError`][eyalsec._errors.ConflictError].

### Install command

```python
cmd = client.get_install_command(m.public_id, attested=True)
print(cmd.script_path, cmd.expires_in)
```

`attested=True` is your confirmation that you are authorized to monitor that machine, the same box the dashboard asks you to tick. The secret works once and expires after ten minutes; treat it like a password (it is left out of the record's `repr`). Calling this for an installed machine resets it for a fresh install, which is how you reinstall or update. The dashboard's Machines page shows the exact command to run with it.

### Rename, change OS, delete

```python
client.rename_machine(m.public_id, "db-primary")
client.set_machine_os("db-primary", "debian_12", "aarch64")
client.delete_machine(m.public_id)  # also deletes every event it reported
```

## CI

A pipeline that holds only an API key can install es-python on its runner, run the tests under it, then ask what they reached.

```python
install = client.ci_install("ci-myrepo", attested=True, distro="ubuntu_24_04", arch="x86_64")
# post install.secret to install.script_path on the runner, run your tests with es-python ...

result = client.ci_findings("ci-myrepo", since=install.server_time, min_severity="high")
print(result.total, "events,", result.findings, "at high or above,", result.new_findings, "new")
for f in result.events:
    print(f.severity, f.where, "new" if f.new else "seen before")
if result.findings:
    raise SystemExit(result.url)
```

Use the server's clock (`install.server_time`) for `since`, not the runner's. The value that reached the sink is deliberately left out of the findings, because CI logs are often public. For a ready-made pipeline step, see [Run es-python in CI](https://eyalsec.com/docs/ci) and the [es-python GitHub Action](https://github.com/EyalSec/es-python-action).
