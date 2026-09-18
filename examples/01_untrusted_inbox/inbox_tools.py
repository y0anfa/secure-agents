"""Tools for the inbox triage example.

Tools live in their own module rather than in the script that runs them,
because the spawn sandbox starts a fresh interpreter and imports them by
name. That is a real constraint of running tools in isolation, so the
examples show it rather than working around it with ``start_method="fork"``.
"""

from pathlib import Path

from secure_agents import tool

MESSAGES = (Path(__file__).parent / "messages").resolve()

# Where a summary is allowed to go. The point of an allowlist is that it is
# shorter than the set of addresses an attacker can think of.
TEAM = frozenset({"ops@corp.example", "support-leads@corp.example"})


@tool(effects="read", exposure=["private", "untrusted"])
def read_message(message_id: str) -> str:
    """Read one message from the support inbox.

    Args:
        message_id: The message id, for example "msg-001".
    """
    path = (MESSAGES / f"{message_id}.txt").resolve()
    if path.parent != MESSAGES:
        raise ValueError(f"{message_id!r} is not a message in this inbox")
    return path.read_text(encoding="utf-8")


@tool(effects="send", exposure="external")
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a colleague.

    Args:
        to: Recipient address.
        subject: Subject line.
        body: Message body.
    """
    # A real implementation would talk to an SMTP server here. The example
    # stops short of that so it can be run without one.
    return f"sent to {to} ({len(body)} bytes)"
