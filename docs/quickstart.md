# Quickstart

Five minutes, no API key. You will end up with an agent that calls a tool and
refuses two others, and you will be able to see why in each case.

## 1. Install

```
pip install secure-agents
```

Nothing else gets installed with it. The core has no dependencies, which is
deliberate: this is a library you are being asked to trust.

For a live model, `pip install 'secure-agents[anthropic]'` and set
`ANTHROPIC_API_KEY`. The rest of this page does not need it.

## 2. Write two tools

A tool is a function. The decorator reads the signature and the docstring to
build the schema the model sees, so the description is not a second thing to
keep in sync.

```python
from secure_agents import tool


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
```

`effects="send"` is the important part of the second one. It tells the policy
layer this tool does something a third party sees and that cannot be undone.

## 3. Write the policy

```python
from secure_agents import Policy, arg

policy = (
    Policy.default_deny()
    .allow("read_report", when=arg("path").under("/srv/reports"))
    .allow("send_email", when=arg("to").in_({"ops@corp.example"}))
)
```

Two grants and a default of deny. Note that the grants are conditional:
`allow("read_report")` on its own would be a much larger grant than this one.
`under()` resolves symlinks before comparing, so a link inside `/srv/reports`
that points at `/etc` does not pass.

## 4. Run it

```python
from secure_agents import Agent, deny_all_approver

agent = Agent(
    model=...,
    tools=[read_report, send_email],
    policy=policy,
    approver=deny_all_approver,
)

result = agent.run("Read the Q3 report and mail it out.")

for record in result.calls:
    print(record.call.name, record.verdict.decision.value, record.verdict.reason)
```

Running `examples/quickstart.py`, which scripts the model so the output is
the same every time:

```
     ok   read_report('/srv/reports/q3.txt')
          allow: matched rule 'allow read_report'
 REFUSED  read_report('/etc/passwd')
          deny: no rule matched and the default is deny
 REFUSED  send_email('someone@elsewhere.example')
          deny: no rule matched and the default is deny
```

Two refusals, each with the rule that produced it. That is the whole idea.

## 5. The part that matters more

The example above refuses calls that never matched a rule. The control that
earns the library its name is different: what happens to calls that *did*
match, after the agent has read something an attacker wrote.

```
ask: the summary goes to the team; escalated from allow because context
     is tainted by tool:read_message
```

Everything a tool returns is marked untrusted, because the agent read it
rather than being told it. Once that is in the context, a side-effecting call
that policy would otherwise allow escalates to a human. Nobody wrote a rule
for that; it is what `effects="send"` bought.

`examples/01_untrusted_inbox/` is that case end to end, with a real injection
in the fixture.

## Then

- Use a real sandbox. The default runs tools in your process:
  `sandbox=Subprocess(egress=Egress.deny_all())`.
- Turn on an audit log: `audit=JsonlAudit("audit.jsonl")`.
- Read [what this does not protect against](limits.md).
