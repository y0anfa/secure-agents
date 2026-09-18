# secure-agents

A small agent SDK where every tool call passes a policy you wrote, and the
ones that fail it are refused with a reason you can read.

Agent frameworks hand the model a set of tools and hope the prompt holds. That
is fine until the agent reads something an attacker wrote, which for any agent
touching email, tickets, web pages or files is a matter of when. secure-agents
puts an ordered, greppable rule list between "the model asked" and "the tool
ran", and tracks where the content in the context came from so the rules can
take that into account.

The core has **no dependencies**. It is a library you are being asked to
trust, so there is not much of it, and nothing else comes with it.

## Install

```
pip install secure-agents
```

## Five minutes

```python
from secure_agents import Agent, Policy, ScriptedModel, arg, deny_all_approver, tool


@tool(effects="read")
def read_report(path: str) -> str:
    """Read a report from the reports directory.

    Args:
        path: Absolute path to the report.
    """
    return open(path).read()


@tool(effects="send")
def send_email(to: str, subject: str, body: str) -> str:
    """Email a colleague.

    Args:
        to: Recipient address.
        subject: Subject line.
        body: Message body.
    """
    return smtp_send(to, subject, body)


# Start from nothing, then grant exactly what the job needs.
policy = (
    Policy.default_deny()
    .allow("read_report", when=arg("path").under("/srv/reports"))
    .allow("send_email", when=arg("to").in_({"ops@corp.example"}))
)

agent = Agent(model=..., tools=[read_report, send_email], policy=policy)
result = agent.run("Read the Q3 report and mail it out.")
```

When the model asks for something outside those two grants, here is what
comes back:

```
     ok   read_report('/srv/reports/q3.txt')
          allow: matched rule 'allow read_report'
 REFUSED  read_report('/etc/passwd')
          deny: no rule matched and the default is deny
 REFUSED  send_email('someone@elsewhere.example')
          deny: no rule matched and the default is deny
```

That is `examples/quickstart.py`, which runs with no API key and is executed
on every commit, so the output above cannot quietly stop being true.

## What that bought you

**A default that denies.** A tool the policy does not mention cannot be
called, so adding a tool to an agent does not silently widen what it can do.

**Conditions on arguments, not just names.** `allow("read_report")` and
`allow("read_report", when=arg("path").under("/srv/reports"))` are very
different grants. `under()` resolves symlinks before comparing, so a link
planted inside the directory does not get out of it.

**Provenance the policy can see.** Everything a tool returns is marked
untrusted, because the agent read it rather than being told it. Once that is
in the context, side-effecting calls escalate to a human automatically:

```
ask: the summary goes to the team; escalated from allow because context
     is tainted by tool:read_message
```

That is the control that makes a successful prompt injection cost an attacker
a human click instead of nothing. It is on by default and you can turn it off
per rule, in a line someone reviewing the policy will see.

**A refusal to build the dangerous shape at all.** An agent that can reach
private data, ingest attacker-authored content, and communicate externally
can be made to exfiltrate. `Agent(...)` checks for that combination at
construction and refuses, before a single token is spent:

```
this agent can reach private data (read_inbox), ingest untrusted content
(fetch_url), and communicate externally (fetch_url). An attacker who controls
what fetch_url returns can make it send read_inbox's output to a destination
of their choosing.
These external tools are not gated once the context is tainted: fetch_url.
Resolve by one of:
  - remove a leg: build two narrower agents instead of one broad one
  - gate the external leg: drop the 'when_tainted=Decision.ALLOW' on those
    rules, or write policy.ask(...) for them, and pass an approver
  - narrow the external tool's arguments, e.g. when=arg('to').in_(['ops@corp'])
  - accept it on the record: Agent(..., acknowledge_exfiltration_risk='<why>')
```

An agent whose policy already gates the external leg passes, which is why
`examples/01_untrusted_inbox/` builds even though it holds all three legs.

## Examples

Each one runs without an API key and ships with tests that assert the attack
is actually stopped.

| | What it shows |
|---|---|
| [Untrusted inbox](examples/01_untrusted_inbox/) | A real prompt injection in the fixture. The exfiltration is denied; the legitimate mail still asks a human. |
| [Repo assistant](examples/02_repo_assistant/) | Path traversal and a symlink escape refused, shell restricted to an allowlist. |
| [Ops approval](examples/03_ops_approval/) | A human gate on the irreversible call, and a hash-chained audit log where a deleted line is detectable. |

## Read next

- [Quickstart](docs/quickstart.md), the same thing with the reasoning spelled out
- [Concepts](docs/concepts.md): agent, tool, policy, sandbox, provenance
- [API reference](docs/API.md)
- [What this does not protect against](docs/limits.md). Read this one before
  you depend on the library.
- [Threat model](docs/THREAT_MODEL.md)

## Status

0.1.0, and the version number is meant literally. The API will change. What
will not change without a major version is the meaning of a policy: if a rule
allowed something in 0.1, it will not silently allow more in 0.2.

Apache-2.0.
