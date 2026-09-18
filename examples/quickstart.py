"""The five-minute version. Everything the README shows, runnable.

Run it with `python examples/quickstart.py`. No API key needed: the model is
scripted so the output is the same every time, including for the test that
keeps the README honest.
"""

from secure_agents import Agent, Policy, ScriptedModel, arg, deny_all_approver, tool


@tool(effects="read")
def read_report(path: str) -> str:
    """Read a report from the reports directory.

    Args:
        path: Absolute path to the report.
    """
    return "Q3 revenue was up 4%."  # a real one would open(path)


@tool(effects="send")
def send_email(to: str, subject: str, body: str) -> str:
    """Email a colleague.

    Args:
        to: Recipient address.
        subject: Subject line.
        body: Message body.
    """
    return f"sent to {to}"


# Start from nothing, then grant exactly what the job needs. A rule is a tool
# name plus a condition on its arguments, and anything no rule matches is
# refused.
policy = (
    Policy.default_deny()
    .allow("read_report", when=arg("path").under("/srv/reports"))
    .allow("send_email", when=arg("to").in_({"ops@corp.example"}))
)

agent = Agent(
    model=ScriptedModel(
        [
            [("read_report", {"path": "/srv/reports/q3.txt"})],
            [("read_report", {"path": "/etc/passwd"})],
            [("send_email", {"to": "someone@elsewhere.example", "subject": "q3", "body": "..."})],
            "Read the Q3 report. Two calls were refused.",
        ]
    ),
    tools=[read_report, send_email],
    policy=policy,
    # No sandbox given, so tools run in this process with its privileges.
    # The examples/ directory shows Subprocess(egress=...) instead.
    approver=deny_all_approver,
)

result = agent.run("Read the Q3 report and mail it out.")

for record in result.calls:
    mark = "ok " if record.ran else "REFUSED"
    print(f"{mark:>8}  {record.call.name}({list(record.call.args.values())[0]!r})")
    print(f"          {record.verdict.decision.value}: {record.verdict.reason}")
