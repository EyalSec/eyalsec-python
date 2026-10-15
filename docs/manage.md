# Triage, rules and settings

Every call on this page except the reads needs a full (not read-only) key.

## Labels and notes

```python
label = client.create_label("false positive", "slate")
client.attach_label(event_id, label.id)
client.set_note(event_id, "Input is an internal constant.")
client.get_event(event_id).comment  # read the note back

# Events carrying a label:
client.iter_events(labels=[label.id])
```

A foreign event id is answered like a missing one, so writes to it raise [`NotFoundError`][eyalsec._errors.NotFoundError].

## Filters

A filter is a standing pattern applied to every events query on a product's Filters page.

```python
f = client.create_filter("^healthcheck$", "blacklist", label="noise")
client.update_filter(f.id, enabled=False)
client.delete_filter(f.id)
```

## Machine rules

A rule matches events and then hides them, shows only them, raises on them, or stops them being sent. `machine=None` is your global scope; otherwise pass a machine's `public_id`.

```python
from eyalsec import RuleMode

rule = client.create_rule(event_pattern="noise", mode=RuleMode.HIDE, label="hide noise")
client.update_rule(rule.id, enabled=False)
client.list_rules(machine=machine.public_id)

# A rule made from one event, matching its sink (and here its stack trace too):
client.create_rule(from_event=event_id, match_on=["trace"], mode=RuleMode.HIDE)
```

Raise rules (`RuleMode.RAISE`) need Raise enabled for your account; check `client.get_account().grant_raise` first.

## Rule templates

```python
templates = client.list_rule_templates()
for t in templates.templates:
    print(t.id, t.owner, t.name, len(t.items))

result = client.apply_rule_template(t.id, machine=None)
print(result.added, "added;", result.skipped_duplicate, "already there;", result.skipped_raise, "need Raise")

# Save what a scope has now as a template of your own:
client.snapshot_rule_template("prod baseline", machine=machine.public_id)
```

## Taint sources

Each setting is `"on"`, `"off"` or `"unset"` (inherit from the level above).

```python
client.get_taint()  # your account defaults
client.set_taint("socket", "on")
client.set_taint("env", "off", machine=machine.public_id)
```

Two keys are spelled differently in a rule's `source`: the setting `weak_random` is the rule source `weak-random`, and `db_rows` is `db`.

## Unique events

```python
client.get_event_uniqueness("python").axes  # ("source", "detail") by default
client.set_event_uniqueness("python", ["source", "detail", "trace"])
client.set_event_uniqueness("python", None, machine=machine.public_id)  # inherit again
```

## Web protection and outbound connections

```python
client.set_web_protection("rate", "on")
client.block_client("203.0.113.7", reason="scanner", hours=24)

client.set_egress(
    [{"action": "deny", "target": "@metadata"}, {"action": "allow", "target": "*.stripe.com:443"}],
    default="deny",
)
```

## Account and key

```python
client.get_account()  # profile, limits, grants
client.get_api_key_info()  # prefix, scope, expiry and last use; never the key
for entry in client.iter_activity(action="machine.create"):
    print(entry.time, entry.description, entry.auth_method)
```

Account changes ask for the same proof the Settings pages do (`password=`, and `totp=` when two-factor sign-in is on). Three of them end the key you are calling with: [`change_password`][eyalsec.EyalSec.change_password], [`revoke_api_key`][eyalsec.EyalSec.revoke_api_key] and [`generate_api_key`][eyalsec.EyalSec.generate_api_key]. The last one returns the new key, and the client switches to it so it keeps working.
