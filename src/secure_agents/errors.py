"""Exception hierarchy for secure-agents.

Everything the SDK raises derives from :class:`SecureAgentsError`, so an
embedding application can catch one class and be sure it has caught us.
"""

from __future__ import annotations


class SecureAgentsError(Exception):
    """Base class for every error raised by secure-agents."""


class SchemaError(SecureAgentsError):
    """A tool signature could not be turned into a schema, or arguments did
    not validate against one."""


class PolicyDenied(SecureAgentsError):
    """A tool call was denied by policy.

    Raised only when the agent is configured with ``on_deny="raise"``. The
    default is to hand the denial back to the model as a tool error, which
    lets it adapt instead of crashing the run.
    """

    def __init__(self, call_name: str, reason: str, rule: str | None = None) -> None:
        self.call_name = call_name
        self.reason = reason
        self.rule = rule
        super().__init__(f"policy denied {call_name!r}: {reason}")


class ApprovalDenied(SecureAgentsError):
    """A human approver declined a tool call that policy routed to them."""


class BudgetExceeded(SecureAgentsError):
    """The run hit its step, tool-call, or wall-clock budget."""


class SandboxError(SecureAgentsError):
    """The sandbox could not run the tool: timeout, crash, resource limit, or
    a transport failure talking to the child process."""


class ToolError(SecureAgentsError):
    """The tool function itself raised.

    The agent catches this and returns it to the model as an error tool
    result rather than aborting the run.
    """


class SecretError(SecureAgentsError):
    """A secret was missing, or something tried to stringify one."""


class ModelRefusal(SecureAgentsError):
    """The model declined the request (``stop_reason == "refusal"``)."""

    def __init__(self, category: str | None, explanation: str | None) -> None:
        self.category = category
        self.explanation = explanation
        super().__init__(f"model refused (category={category}): {explanation}")
