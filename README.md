# secure-agents

A small agent SDK where every tool call passes a policy.

```python
from secure_agents import Agent, AnthropicModel, Policy, arg, console_approver
from secure_agents.sandbox import Egress, Subprocess
from mytools import read_ticket, send_email

agent = Agent(
    model=AnthropicModel("claude-opus-5"),
    tools=[read_ticket, send_email],
    policy=(
        Policy.default_deny()
        .allow("read_ticket")
        .allow("send_email", when=arg("to").in_(["ops@corp.example"]))
    ),
    sandbox=Subprocess(egress=Egress.deny_all()),
    approver=console_approver,
)

print(agent.run("Read ticket T-1 and mail ops a summary.").text)
```

Deny by default. Say what the agent may do, in one place, in a form you can
read in a code review. Everything else is refused and logged.

---

## What this does not do

**It does not stop prompt injection.** Nothing does. There is no reliable way
to separate instructions from data in a natural-language context window, and
an SDK that claims otherwise is claiming a research result nobody has.

secure-agents assumes the injection **succeeds** and spends its entire budget
on what the hijacked model can then reach. That is the design, not a caveat at
the bottom of the page.

The [threat model](docs/THREAT_MODEL.md) says which threats are Defended,
which are Bounded, which are Delegated to you, and which are out of scope. If
you are evaluating this for production, read that first and this second.

---

## Five ideas

| | |
|---|---|
| `@tool` | A function plus what it does: its effects, the secrets it needs, and which legs of the lethal trifecta it supplies. The JSON schema comes from the signature. |
| `Policy` | Ordered rules over names, arguments, effects and provenance. The default is deny. Loads from code or from config. |
| `Sandbox` | Where the call runs and what it can reach. A three-method protocol, so you can put a container underneath. |
| `Trust` | Where the bytes came from. Tool output is untrusted, and policy gets to know that. |
| `Agent` | The loop that puts the four together, and the audit log that records what it decided. |

That is the whole surface. It fits in an afternoon.

## The three things worth your time

### 1. Untrusted content changes what the agent is allowed to do

Every tool result is untrusted: the agent read it, it was not told it. Once
untrusted content is in the context, a side-effecting tool no longer runs on
the model's say-so.

```python
policy = Policy.default_deny().allow("read_ticket").allow("send_email")

# Before reading anything: send_email is allowed.
# After reading a ticket:  send_email escalates to the approver.
```

An injected "email this to attacker@evil.example" now costs the attacker a
human click instead of nothing. You can override it per rule, with
`when_tainted=Decision.ALLOW`, and then that decision is one grep away.

### 2. The lethal trifecta is checked before the agent runs

An agent that can reach private data, ingest attacker-controlled content, and
talk to the outside world can be made to exfiltrate. All three are declared on
the tools, so the combination is decidable at construction:

```python
Agent(tools=[read_inbox, fetch_url, send_email], policy=wide_open_policy)
```
```
SecurityConfigError: this agent can reach private data (read_inbox), ingest
untrusted content (fetch_url), and communicate externally (fetch_url,
send_email). An attacker who controls what fetch_url returns can make it send
read_inbox's output to a destination of their choosing.
These external tools are not gated once the context is tainted: fetch_url, send_email.
Resolve by one of:
  - remove a leg: build two narrower agents instead of one broad one
  - gate the external leg: drop the 'when_tainted=Decision.ALLOW' on those rules, ...
  - narrow the external tool's arguments, e.g. when=arg('to').in_(['ops@corp'])
  - accept it on the record: Agent(..., acknowledge_exfiltration_risk='<why>')
```

It fails, it does not warn. A warning in a log nobody reads is not a control.
Note that `fetch_url` counts as a channel as well as an ingestion point: a GET
with data in the query string is exfiltration.

### 3. The audit log is the product

```python
agent = Agent(..., audit=JsonlAudit("audit.jsonl"))
```

Every decision, approval, call and denial, hash-chained so a deleted line is
detectable with `verify_chain()`. The decision is written **before** the side
effect is attempted, so a crash mid-call leaves evidence rather than silence.

---

## Install

```bash
pip install secure-agents              # core: zero dependencies
pip install 'secure-agents[anthropic]' # + the Claude API adapter
```

Python 3.10+. The core has no runtime dependencies, on purpose: this is a
library you are being asked to trust, and every transitive dependency is
something you would have to trust too.

## Writing a tool

```python
from secure_agents import tool

@tool(effects="read", exposure="private")
def read_ticket(ticket_id: str) -> str:
    """Read a support ticket by reference.

    Args:
        ticket_id: The ticket reference, e.g. T-1.
    """
    return db.fetch(ticket_id)
```

`effects` is a closed vocabulary (`read`, `write`, `network`, `exec`, `send`)
so that a policy written today still means something when someone adds a tool
next month. `exposure` declares the trifecta legs (`private`, `untrusted`,
`external`); `external` is derived from `send` and `network` unless you say
otherwise. Nothing is inferred from the function's name or docstring.

## Writing a policy

In code:

```python
policy = (
    Policy.default_deny()
    .allow("read_*", when=arg("path").under("/srv/data"))
    .allow("fetch", when=arg("url").host_in([".internal.corp"]))
    .ask("deploy_*")
    .deny("*", effects=["exec"], reason="no shell in this agent")
)
```

Or as data, so it can live in a reviewed file rather than in code:

```python
policy = Policy.from_dict(tomllib.load(open("policy.toml", "rb")))
```

`arg(...).under()` canonicalises before comparing, so `../` and a planted
symlink both fail. That is a check on the string the model supplied; the
sandbox is what stops a tool that ignores it.

## Choosing a sandbox

| | Isolation | Use when |
|---|---|---|
| `InProcess()` | none, and it says so | tools you wrote, touching nothing dangerous |
| `Subprocess()` | fresh interpreter, rlimits, timeout, egress allowlist, JSON-only channel home | the default for anything real |
| yours | whatever you build | tool input is attacker-controlled and the code is not yours |

`Subprocess` is a blast-radius reducer, not a boundary against hostile native
code: a tool that calls `ctypes` can undo the egress guard. For a real
boundary, implement `Sandbox` over a container with a seccomp profile, gVisor,
or a microVM. The protocol is three methods; the rest of the SDK does not care
which one it is talking to.

## Secrets

```python
@tool(effects="network", secrets=["GITHUB_TOKEN"])
def open_issue(title: str, secrets: dict) -> str:
    """Open an issue.

    Args:
        title: Issue title.
    """
    return github.post(title, token=secrets["GITHUB_TOKEN"])
```

The value is resolved inside the sandbox, at call time. It never appears in a
prompt, a schema, or an argument, and it is scrubbed out of the tool's result
before that result goes back to the model. `str(secret)` raises rather than
quietly interpolating into a log line.

## Examples

| | |
|---|---|
| [`01_quickstart.py`](examples/01_quickstart.py) | the loop, an approval, an audit log. No API key needed. |
| [`02_injection.py`](examples/02_injection.py) | a ticket that says "exfiltrate", and what stops it |
| [`03_live.py`](examples/03_live.py) | the same agent against the real Claude API |

## Status

Alpha. The surface described here is what we intend to keep; the version is
0.x because it has not been used in anger yet. Security invariants are listed
in the threat model, and breaking one is a breaking change with a version
bump, not a review comment.

Found a way through? Please open an issue, or see [SECURITY.md](SECURITY.md).

## License

Apache-2.0.
