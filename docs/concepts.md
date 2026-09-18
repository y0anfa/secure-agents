# Concepts

Five ideas. If you understand these you have understood the library.

## Tool

A Python function plus the metadata the rest of the SDK needs to reason about
it. The JSON schema comes from the signature and the docstring, so there is
one place to change when a tool changes.

```python
@tool(effects="read", exposure="private")
def read_note(path: str) -> str:
    """Read a note from disk.

    Args:
        path: Absolute path to the note.
    """
    return open(path).read()
```

`effects` is a closed vocabulary: `read`, `write`, `network`, `exec`, `send`.
Closed on purpose, because policy is only useful if the words mean the same
thing in every tool module. A rule written about `send` applies to a tool
added next month without anyone remembering to update a list.

`exposure` declares which legs of the lethal trifecta a tool supplies:
`private` (reaches data you would not publish), `untrusted` (returns content
an outsider may have authored), `external` (can move bytes out). The last is
derived from `send` and `network` unless you say otherwise.

## Policy

An ordered list of rules with a default, and the default is deny. First match
wins.

```python
policy = (
    Policy.default_deny()
    .allow("read_note", when=arg("path").under("/srv/notes"))
    .ask("send_email", reason="mail leaves the building")
)
```

Rules match on tool name globs, on `effects`, and on argument predicates:
`under`, `host_in`, `in_`, `equals`, `matches`, `max_len`, combined with
`all_of`, `any_of`, `not_`.

`Policy.from_dict` loads the same policy from TOML, YAML or JSON, so it can
live in a reviewed config file instead of in code. `policy.describe()` prints
it as readable lines for a log or a review.

## Provenance

Every piece of content in the context carries a trust level: `TRUSTED` (your
system prompt), `USER` (what the human typed), `UNTRUSTED` (everything the
agent read rather than was told).

Anything a tool returns is untrusted, without exception, because the agent
read it. Once untrusted content is in the context the run is *tainted*, and
policy can see that when it decides.

The default that falls out: an `allow` on a side-effecting tool becomes an
`ask` once tainted. You did not write that rule and you can override it per
rule with `when_tainted=`, which is a line a reviewer will notice.

## Sandbox

Where the tool actually runs.

`InProcess()` is the default and is no isolation at all. `Subprocess()` gives
a fresh interpreter with resource limits, a minimal environment, and an
egress allowlist:

```python
sandbox = Subprocess(egress=Egress.allow("api.github.com"), memory_mb=256)
```

Under `spawn` the child inherits no memory, which is why tools have to live
in an importable module rather than in your `__main__` script. That is a real
constraint and the examples show it rather than working around it.

See [limits](limits.md) for what this containment is and is not.

## Audit

Every policy decision, approval, call and result, including the refused ones.

`MemoryAudit` for tests, `JsonlAudit(path)` for a hash-chained file where a
deleted line is detectable with `verify_chain`, `NullAudit` (the default) so
the SDK writes no files unless you ask it to.

The events are stable strings: `policy.decision`, `call.denied`,
`approval.resolved`, `call.completed`. They are meant to be shipped to
whatever you already use for logs.

## The trifecta check

Not a sixth idea so much as a consequence of the other five, but it is the
one that fires before anything runs.

Three properties together make an agent an exfiltration channel: it can reach
private data, it ingests content an attacker may have authored, and it can
move bytes outside the boundary. Any two are usually fine. All three, with
nothing gating the third, means whoever controls the untrusted content
chooses where the private data goes.

`Agent(...)` computes this from the `exposure` your tools declare and from
what the policy can still allow once the context is tainted, then refuses to
construct. The error names the tools supplying each leg and lists the ways
out, including `acknowledge_exfiltration_risk="<why>"`, which is on the
record in the code and in the audit log rather than a flag someone flipped.

The check is structural. It does not look at what the model does, only at
what the configuration makes possible, which is why it can run at startup.


## Putting it together

```python
agent = Agent(
    model=AnthropicModel(),
    tools=[read_note, send_email],
    policy=policy,
    sandbox=Subprocess(egress=Egress.deny_all()),
    approver=console_approver,
    audit=JsonlAudit("audit.jsonl"),
)
```

The loop, once per tool call the model asks for:

```
arguments validated against the schema
  -> policy decides: allow, ask, deny
  -> (ask) a human answers
  -> sandbox runs it, secrets resolved on the far side
  -> result redacted, marked untrusted, fed back
  -> context is now tainted, and policy knows
```

There is no step where the model's request reaches a function directly.
