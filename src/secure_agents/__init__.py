"""secure-agents: a small agent SDK where every tool call passes a policy.

The whole surface is five ideas:

    Agent    the loop: model, tools, policy, sandbox, audit
    tool     a decorator that turns a function into something the model can call
    Policy   the rules that decide whether a call runs, asks, or is refused
    Sandbox  where the call runs, and what it can reach from there
    Trust    where content came from, which policy gets to reason about

A first agent, in full:

    from secure_agents import Agent, AnthropicModel, Policy, arg, tool
    from secure_agents.sandbox import Subprocess, Egress
    from mytools import read_report, send_email

    policy = (
        Policy.default_deny()
        .allow("read_report", when=arg("path").under("/srv/reports"))
        .ask("send_email")
    )

    agent = Agent(
        model=AnthropicModel(),
        tools=[read_report, send_email],
        policy=policy,
        sandbox=Subprocess(egress=Egress.deny_all()),
        approver=console_approver,
    )

    print(agent.run("Summarize this week's reports and mail them to ops@corp").text)
"""

from .agent import Agent, CallRecord, RunResult, Step, console_approver, deny_all_approver
from .audit import Event, JsonlAudit, MemoryAudit, NullAudit, verify_chain
from .errors import (
    ApprovalDenied,
    BudgetExceeded,
    ModelRefusal,
    PolicyDenied,
    SandboxError,
    SchemaError,
    SecretError,
    SecureAgentsError,
    ToolError,
)
from .models import AnthropicModel, Model, ModelResponse, ScriptedModel, ToolUse
from .policy import Decision, Policy, Rule, ToolCall, Verdict, all_of, any_of, arg, not_, tainted
from .provenance import Provenance, Source, Trust
from .sandbox import Egress, InProcess, Sandbox, Subprocess, unenforced_limits
from .secrets import Secret
from .tools import EFFECTS, EXPOSURES, Tool, ToolSpec, tool
from .trifecta import SecurityConfigError, Trifecta, find_trifecta

__version__ = "0.1.0"

__all__ = [
    "Agent",
    "AnthropicModel",
    "ApprovalDenied",
    "BudgetExceeded",
    "CallRecord",
    "Decision",
    "EFFECTS",
    "EXPOSURES",
    "Egress",
    "Event",
    "InProcess",
    "JsonlAudit",
    "MemoryAudit",
    "Model",
    "ModelRefusal",
    "ModelResponse",
    "NullAudit",
    "Policy",
    "PolicyDenied",
    "Provenance",
    "RunResult",
    "Rule",
    "Sandbox",
    "SandboxError",
    "SchemaError",
    "ScriptedModel",
    "Secret",
    "SecretError",
    "SecureAgentsError",
    "SecurityConfigError",
    "Source",
    "Step",
    "Subprocess",
    "Tool",
    "Trifecta",
    "ToolCall",
    "ToolError",
    "ToolSpec",
    "ToolUse",
    "Trust",
    "Verdict",
    "__version__",
    "all_of",
    "any_of",
    "arg",
    "find_trifecta",
    "console_approver",
    "deny_all_approver",
    "not_",
    "tainted",
    "tool",
    "unenforced_limits",
    "verify_chain",
]
