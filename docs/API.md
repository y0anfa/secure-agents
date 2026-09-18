# API reference

Everything below is importable from `secure_agents`. There is nothing else.

## `@tool`

```python
tool(fn=None, *, name=None, effects=(), secrets=(), timeout_s=30.0, exposure=())
```

Turns a function into a `Tool`. The JSON schema is derived from the signature
and the docstring; the docstring is required, because the model needs it.

| argument | meaning |
|---|---|
| `name` | override the tool name the model sees. Defaults to the function name. |
| `effects` | one or more of `read`, `write`, `network`, `exec`, `send`. A closed vocabulary: policy is only useful if the words mean the same thing across tool modules. |
| `secrets` | names resolved inside the sandbox and passed as a `secrets` dict. Excluded from the model-facing schema. |
| `timeout_s` | per-call wall clock. The sandbox's own limit wins if it is lower. |
| `exposure` | one or more of `private`, `untrusted`, `external`. The lethal-trifecta legs. `external` is added automatically when `effects` contains `send` or `network`. |

Supported parameter types: `str`, `int`, `float`, `bool`, `Literal[...]`,
`Optional[X]`, `list[X]`, `dict`. `*args` and `**kwargs` are rejected: a tool
needs an explicit signature for the schema to be checkable.

`ToolSpec.effect_class` gives the threat model's four-value vocabulary:
`Pure`, `Read`, `Write`, `External`.

## `Policy`

First match wins; the default is `DENY`.

```python
Policy.default_deny()
  .allow(tools, *, when=None, when_tainted=None, effects=(), reason="", name="")
  .ask(tools, *, when=None, effects=(), reason="", name="")
  .deny(tools, *, when=None, effects=(), reason="", name="")
```

`tools` is a glob over names. `effects` narrows the rule to tools declaring at
least one of them. `when` is a predicate over the call.

`when_tainted` is what the rule decides once untrusted content is in the
context. Left unset it means: **`ASK` for side-effecting tools, unchanged for
read-only ones.** Set it explicitly to override, and expect to justify it.

### Predicates

```python
arg("path").under("/srv/data")     # canonicalised, symlink-following containment
arg("url").host_in([".corp.net"])  # leading dot allows subdomains
arg("to").in_(["ops@corp"])
arg("name").equals("x")
arg("q").matches(r"[a-z]+")        # fullmatch
arg("body").max_len(4096)
all_of(p, q)   any_of(p, q)   not_(p)   tainted
```

A predicate that raises produces `DENY`, not a fall-through to a later rule.

### From config

```python
Policy.from_dict(
    {
        "default": "deny",
        "rules": [
            {"tools": "read_*", "decision": "allow", "when": {"arg": "path", "under": "/srv/data"}},
            {"tools": "*", "decision": "ask", "effects": ["send"]},
        ],
    }
)
```

Config predicates: `under`, `equals`, `in`, `matches`, `host_in`, `max_len`.

### Introspection

```python
policy.describe()  # the rules as readable lines
policy.decide(call, spec)  # -> Verdict(decision, reason, rule, escalated)
policy.may_ask(specs)  # does this policy need an approver?
policy.can_allow_when_tainted(spec)  # static, over-approximating
```

## `Agent`

```python
Agent(*, model, tools, policy,
      sandbox=InProcess(), approver=None, audit=NullAudit(), system=None,
      secret_provider=None, max_steps=8, max_tool_calls=32, deadline_s=300.0,
      on_deny="report", acknowledge_exfiltration_risk=None)
```

Raises `ValueError` if the policy can ask but no approver was given, and
`SecurityConfigError` if the tools and policy together complete the lethal
trifecta. Both at construction.

`run(prompt) -> RunResult` with `.text`, `.steps`, `.calls`, `.denied`,
`.provenance`, `.run_id`. Each `CallRecord` carries `.call`, `.verdict`,
`.approved`, `.result`, `.error`, `.duration_s`.

`on_deny="report"` hands the refusal back to the model as an error tool result
so it can try something else. `on_deny="raise"` stops the run with
`PolicyDenied` or `ApprovalDenied`.

Budgets raise `BudgetExceeded`. `max_tool_calls` is checked before the calls in
a step run, not after.

### Approvers

`Callable[[ToolCall, Verdict], bool]`. Two are provided: `console_approver`
(stdin) and `deny_all_approver` (refuses everything that needs a human, which
is the right default for an unattended run). An approver is shown the
**resolved** call and the policy's reason. Never show it model-authored text
as if it were the request.

## Sandboxes

```python
InProcess()
Subprocess(*, timeout_s=30.0, memory_mb=512, cpu_s=10, max_write_mb=64,
           egress=Egress.deny_all(), env=None, start_method="spawn")
```

`Egress.deny_all()`, `Egress.allow("host", ".wildcard.host")`,
`Egress.unrestricted()`.

`spawn` re-imports the calling module, so tools must live in an importable
module and a script that runs an agent needs
`if __name__ == "__main__":`. `start_method="fork"` lifts both requirements
and most of the isolation.

### Limits that the platform will not enforce

Not every rlimit works everywhere. Darwin accepts `RLIMIT_AS` and then ignores
it, so `memory_mb` is a no-op on macOS; a platform with no `resource` module
has none of them. A limit that silently does nothing is worse than no limit,
because it reads as a control, so it is reported rather than claimed:

```python
from secure_agents import Subprocess, unenforced_limits

unenforced_limits()          # for this platform, e.g. frozenset({"memory_mb"})
unenforced_limits("darwin")  # ask about another one
Subprocess().unenforced      # what this sandbox will not enforce
Subprocess().describe()
# "subprocess(spawn), 512MB NOT ENFORCED on darwin, 10s cpu, ..."
```

`describe()` is what the audit log records, so a run on macOS says it had no
memory cap rather than claiming one it never had.

Separately, a limit that *should* have applied on this platform and could not
be set is fail-closed: the tool's result is discarded and `SandboxError` names
the limit. Previously such a failure was swallowed and the run continued as if
fully sandboxed.

Implement `Sandbox` yourself for a real boundary:

```python
class MySandbox:
    def execute(self, tool, args, secrets) -> Any: ...
    def describe(self) -> str: ...
```

Raise `ToolError` for the tool's fault and `SandboxError` for the boundary's.
Return something JSON-serializable.

## Provenance

```python
Trust.TRUSTED | Trust.USER | Trust.UNTRUSTED
Provenance.from_user().with_source(Source(Trust.UNTRUSTED, "tool:fetch"))
provenance.tainted  # bool
provenance.describe()  # "tainted by tool:fetch"
```

Calls made in the same step share the provenance the step started with: the
model chose them before it saw any of that step's results, so they were not
influenced by them. Taint applies from the next step.

## Secrets

```python
Secret("GITHUB_TOKEN")  # a handle
Secret("X", provider=my_lookup)  # anything callable taking a name
secret.reveal()  # the value; str(secret) raises
```

## Audit

```python
NullAudit()  MemoryAudit()  JsonlAudit(path, fsync=False)
verify_chain(path) -> (ok, first_bad_line)
```

Event types are constants on `secure_agents.audit`: `run.started`,
`model.turn`, `call.requested`, `call.invalid`, `policy.decision`,
`approval.requested`, `approval.resolved`, `call.completed`, `call.failed`,
`call.denied`, `budget.exceeded`, `run.finished`.

## Models

```python
AnthropicModel(model="claude-opus-5", *, max_tokens=16000, client=None,
               effort=None, thinking="adaptive", strict_tools=True,
               fallbacks="default", extra_params=None)
ScriptedModel(script)   # ["final text"] or [[("tool", {...})], ...]
```

`Model` is one method:

```python
def complete(self, *, system, messages, tools) -> ModelResponse: ...
```

Messages are Anthropic-shaped dicts. `strict_tools` sends `strict: true` so
tool arguments are guaranteed to validate against the schema. `fallbacks`
turns on server-side refusal fallback; set it to `None` if you need the
refusal surfaced as `ModelRefusal` rather than routed to another model.

The loop lives in `Agent`, not in the SDK's tool runner, because the policy
check has to sit between "the model asked" and "the tool ran" and has to be
able to refuse.

## Errors

`SecureAgentsError` is the base. `SchemaError`, `PolicyDenied`,
`ApprovalDenied`, `BudgetExceeded`, `SandboxError` (and `EgressDenied`),
`ToolError`, `SecretError`, `ModelRefusal`, `SecurityConfigError`.
