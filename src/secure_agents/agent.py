"""The loop.

One pass looks like this:

    model asks for tools
      -> arguments validated against the schema
      -> policy decides: allow, ask, deny
      -> (ask) a human answers
      -> sandbox runs it, with secrets resolved on the far side
      -> result redacted, marked untrusted, fed back
      -> context is now tainted, and policy knows

Everything in that list is a thing you can inspect, log and test. There is no
step where the model's request goes straight to a function call.

Denials are reported to the model as errors by default rather than raised. An
agent that is told "no" can pick a different approach; an agent that crashes
just means a human has to do the task by hand. Set ``on_deny="raise"`` when
you would rather the run stop.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from . import audit as audit_events
from .audit import AuditLog, Event, NullAudit
from .errors import (
    ApprovalDenied,
    BudgetExceeded,
    PolicyDenied,
    SandboxError,
    SchemaError,
    ToolError,
)
from .models import Model, ToolUse
from .policy import Decision, Policy, ToolCall, Verdict
from .provenance import Provenance, Source, Trust
from .sandbox import InProcess, Sandbox
from .secrets import Redactor, Secret
from .tools import Tool, validate_args
from .trifecta import check as check_trifecta

Approver = Callable[[ToolCall, Verdict], bool]


@dataclass
class CallRecord:
    """What happened to one tool call."""

    call: ToolCall
    verdict: Verdict
    approved: bool | None = None
    result: Any = None
    error: str | None = None
    duration_s: float = 0.0

    @property
    def ran(self) -> bool:
        return (
            self.error is None
            and self.approved is not False
            and self.verdict.decision
            in (
                Decision.ALLOW,
                Decision.ASK,
            )
        )


@dataclass
class Step:
    index: int
    text: str
    calls: list[CallRecord] = field(default_factory=list)


@dataclass
class RunResult:
    """The outcome of :meth:`Agent.run`."""

    text: str
    steps: list[Step]
    provenance: Provenance
    run_id: str
    stop_reason: str | None = None

    @property
    def calls(self) -> list[CallRecord]:
        return [record for step in self.steps for record in step.calls]

    @property
    def denied(self) -> list[CallRecord]:
        return [r for r in self.calls if r.verdict.decision is Decision.DENY or r.approved is False]

    def __str__(self) -> str:  # pragma: no cover - display only
        return self.text


def console_approver(call: ToolCall, verdict: Verdict) -> bool:
    """Ask on stdin. Fine for a CLI, not for anything running unattended."""
    print(f"\n  Tool:    {call.name}")
    print(f"  Args:    {call.args}")
    print(f"  Context: {call.provenance.describe()}")
    print(f"  Policy:  {verdict.reason}")
    return input("  Allow this call? [y/N] ").strip().lower() in ("y", "yes")


def deny_all_approver(call: ToolCall, verdict: Verdict) -> bool:
    """Refuse everything that needs a human. The safe choice for a batch run
    where nobody is watching: the agent still finishes, without the calls that
    needed a decision."""
    return False


class Agent:
    """A model, some tools, and the rules for putting them together.

    Args:
        model: Anything implementing :class:`~secure_agents.models.Model`.
        tools: The tools this agent may use. A tool the agent does not hold
            cannot be called, whatever the model says.
        policy: The decision layer. Denies by default.
        sandbox: Where tools run. ``InProcess()`` if omitted, which is no
            isolation; say so out loud in your own code.
        approver: Called for ``ASK`` decisions. Required if the policy can ask.
        audit: Where the record goes. Nothing is written unless you pass one.
        system: System prompt. Trusted content, unlike everything a tool returns.
        max_steps: Model turns per run.
        max_tool_calls: Tool calls per run.
        deadline_s: Wall-clock budget for the whole run.
        on_deny: ``"report"`` tells the model; ``"raise"`` stops the run.
        acknowledge_exfiltration_risk: Why this agent may hold all three legs
            of the lethal trifecta anyway. Construction fails without it; the
            reason is recorded in the audit log.

    Raises:
        SecurityConfigError: The tools and policy together describe an agent
            that can be made to exfiltrate private data. See
            :mod:`secure_agents.trifecta`.
    """

    def __init__(
        self,
        *,
        model: Model,
        tools: Iterable[Tool],
        policy: Policy,
        sandbox: Sandbox | None = None,
        approver: Approver | None = None,
        audit: AuditLog | None = None,
        system: str | None = None,
        secret_provider: Callable[[str], str | None] | None = None,
        max_steps: int = 8,
        max_tool_calls: int = 32,
        deadline_s: float = 300.0,
        on_deny: str = "report",
        acknowledge_exfiltration_risk: str | None = None,
    ) -> None:
        self.model = model
        self.tools = {t.name: t for t in tools}
        self.policy = policy
        self.sandbox = sandbox or InProcess()
        self.audit = audit if audit is not None else NullAudit()
        self.system = system
        self.max_steps = max_steps
        self.max_tool_calls = max_tool_calls
        self.deadline_s = deadline_s
        if on_deny not in ("report", "raise"):
            raise ValueError("on_deny must be 'report' or 'raise'")
        self.on_deny = on_deny
        self._secret_provider = secret_provider

        specs = [t.spec for t in self.tools.values()]

        # Before anything else: can this agent be made to exfiltrate? The
        # answer is computable from the tools and the policy, so it is decided
        # here rather than at 3am.
        self.acknowledged_risk = acknowledge_exfiltration_risk
        self.trifecta = check_trifecta(
            specs,
            ungated_external=[
                spec.name
                for spec in specs
                if spec.effect_class == "External" and policy.can_allow_when_tainted(spec)
            ],
            acknowledged=acknowledge_exfiltration_risk,
        )

        if approver is None and policy.may_ask(specs):
            raise ValueError(
                "this policy can route calls to a human (an 'ask' rule, or an "
                "'allow' on a side-effecting tool that escalates when the context "
                "is tainted) but no approver was given. Pass approver=console_approver "
                "for an interactive run, or approver=deny_all_approver for an "
                "unattended one."
            )
        self.approver = approver or deny_all_approver

    # -- running -----------------------------------------------------------

    def run(self, prompt: str, *, user_label: str = "user") -> RunResult:
        run_id = uuid.uuid4().hex[:12]
        started = time.monotonic()
        provenance = Provenance.from_user(user_label)
        messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
        steps: list[Step] = []
        calls_made = 0

        self._record(
            audit_events.RUN_STARTED,
            run_id=run_id,
            model=self.model.describe(),
            sandbox=self.sandbox.describe(),
            tools=sorted(self.tools),
            policy=self.policy.describe(),
            trifecta_legs={
                "private": list(self.trifecta.private),
                "untrusted": list(self.trifecta.untrusted),
                "external": list(self.trifecta.external),
            },
            acknowledged_exfiltration_risk=self.acknowledged_risk,
        )

        for index in range(self.max_steps):
            self._check_clock(run_id, started)
            response = self.model.complete(
                system=self.system, messages=messages, tools=[t.spec for t in self.tools.values()]
            )
            self._record(
                audit_events.MODEL_TURN,
                run_id=run_id,
                step=index,
                stop_reason=response.stop_reason,
                tool_calls=[u.name for u in response.tool_uses],
                usage=response.usage,
            )
            step = Step(index=index, text=response.text)
            steps.append(step)

            if not response.tool_uses:
                self._record(
                    audit_events.RUN_FINISHED, run_id=run_id, steps=len(steps), reason="end_turn"
                )
                return RunResult(response.text, steps, provenance, run_id, response.stop_reason)

            if calls_made + len(response.tool_uses) > self.max_tool_calls:
                self._record(audit_events.BUDGET_EXCEEDED, run_id=run_id, budget="max_tool_calls")
                raise BudgetExceeded(f"run would exceed max_tool_calls={self.max_tool_calls}")

            messages.append({"role": "assistant", "content": response.content_blocks})

            # Every call in this step was chosen before the model saw any of
            # this step's results, so they all share the provenance the context
            # had when the step began. Taint applies from the next step on.
            step_provenance = provenance
            results: list[dict[str, Any]] = []
            for use in response.tool_uses:
                self._check_clock(run_id, started)
                calls_made += 1
                record, block, new_source = self._handle(use, step_provenance, index, run_id)
                step.calls.append(record)
                results.append(block)
                if new_source is not None:
                    provenance = provenance.with_source(new_source)

            messages.append({"role": "user", "content": results})

        self._record(audit_events.BUDGET_EXCEEDED, run_id=run_id, budget="max_steps")
        raise BudgetExceeded(f"run did not finish within max_steps={self.max_steps}")

    # -- one call ----------------------------------------------------------

    def _handle(
        self, use: ToolUse, provenance: Provenance, step: int, run_id: str
    ) -> tuple[CallRecord, dict[str, Any], Source | None]:
        call = ToolCall(id=use.id, name=use.name, args=use.args, provenance=provenance, step=step)
        self._record(
            audit_events.CALL_REQUESTED,
            run_id=run_id,
            step=step,
            call_id=call.id,
            tool=call.name,
            args=call.args,
            tainted=provenance.tainted,
        )

        tool = self.tools.get(use.name)
        if tool is None:
            # The model asked for something this agent does not have. Not an
            # attack on its own, but worth seeing in the log if it repeats.
            return self._reject(
                call,
                Verdict(Decision.DENY, "no such tool", rule=None),
                f"No tool named {use.name!r} is available.",
                run_id,
                audit_events.CALL_INVALID,
            )

        try:
            validate_args(tool.spec.input_schema, call.args)
        except SchemaError as exc:
            return self._reject(
                call,
                Verdict(Decision.DENY, f"invalid arguments: {exc}", rule=None),
                f"Invalid arguments for {use.name}: {exc}",
                run_id,
                audit_events.CALL_INVALID,
            )

        verdict = self.policy.decide(call, tool.spec)
        self._record(
            audit_events.POLICY_DECISION,
            run_id=run_id,
            call_id=call.id,
            tool=call.name,
            decision=verdict.decision.value,
            reason=verdict.reason,
            rule=verdict.rule,
            escalated=verdict.escalated,
        )

        record = CallRecord(call=call, verdict=verdict)

        if verdict.decision is Decision.DENY:
            self._record(
                audit_events.CALL_DENIED,
                run_id=run_id,
                call_id=call.id,
                tool=call.name,
                reason=verdict.reason,
            )
            if self.on_deny == "raise":
                raise PolicyDenied(call.name, verdict.reason, verdict.rule)
            record.error = verdict.reason
            return (
                record,
                _error_block(call.id, f"Denied by policy: {verdict.reason}"),
                None,
            )

        if verdict.decision is Decision.ASK:
            self._record(
                audit_events.APPROVAL_REQUESTED,
                run_id=run_id,
                call_id=call.id,
                tool=call.name,
                reason=verdict.reason,
            )
            approved = bool(self.approver(call, verdict))
            record.approved = approved
            self._record(
                audit_events.APPROVAL_RESOLVED,
                run_id=run_id,
                call_id=call.id,
                tool=call.name,
                approved=approved,
            )
            if not approved:
                if self.on_deny == "raise":
                    raise ApprovalDenied(f"{call.name} was not approved")
                record.error = "not approved"
                return (
                    record,
                    _error_block(call.id, "A human declined this call."),
                    None,
                )

        return self._execute(tool, record, run_id)

    def _execute(
        self, tool: Tool, record: CallRecord, run_id: str
    ) -> tuple[CallRecord, dict[str, Any], Source | None]:
        call = record.call
        redactor = Redactor()
        secrets: dict[str, str] = {}
        for name in tool.spec.secrets:
            secret = Secret(name, self._secret_provider) if self._secret_provider else Secret(name)
            try:
                value = secret.reveal()
            except Exception as exc:
                record.error = str(exc)
                self._record(
                    audit_events.CALL_FAILED,
                    run_id=run_id,
                    call_id=call.id,
                    tool=call.name,
                    error=str(exc),
                )
                return record, _error_block(call.id, f"Configuration error: {exc}"), None
            secrets[name] = value
            redactor.register(name, value)

        started = time.monotonic()
        try:
            result = self.sandbox.execute(tool, call.args, secrets)
        except (ToolError, SandboxError) as exc:
            record.error = str(exc)
            record.duration_s = time.monotonic() - started
            self._record(
                audit_events.CALL_FAILED,
                run_id=run_id,
                call_id=call.id,
                tool=call.name,
                error=str(exc),
                duration_s=round(record.duration_s, 4),
            )
            return record, _error_block(call.id, redactor.redact(str(exc))), None

        record.duration_s = time.monotonic() - started
        text = redactor.redact(_as_text(result))
        record.result = text
        self._record(
            audit_events.CALL_COMPLETED,
            run_id=run_id,
            call_id=call.id,
            tool=call.name,
            duration_s=round(record.duration_s, 4),
            result_bytes=len(text),
        )
        # Whatever a tool returns, the agent read it rather than was told it.
        # From here on the context is tainted and policy knows.
        return (
            record,
            {"type": "tool_result", "tool_use_id": call.id, "content": text},
            Source(Trust.UNTRUSTED, f"tool:{call.name}"),
        )

    # -- plumbing ----------------------------------------------------------

    def _reject(
        self,
        call: ToolCall,
        verdict: Verdict,
        message: str,
        run_id: str,
        event_type: str,
    ) -> tuple[CallRecord, dict[str, Any], None]:
        self._record(
            event_type, run_id=run_id, call_id=call.id, tool=call.name, reason=verdict.reason
        )
        record = CallRecord(call=call, verdict=verdict, error=verdict.reason)
        return record, _error_block(call.id, message), None

    def _check_clock(self, run_id: str, started: float) -> None:
        if time.monotonic() - started > self.deadline_s:
            self._record(audit_events.BUDGET_EXCEEDED, run_id=run_id, budget="deadline_s")
            raise BudgetExceeded(f"run exceeded its {self.deadline_s}s deadline")

    def _record(self, event_type: str, **data: Any) -> None:
        self.audit.record(Event(event_type, data))


def _error_block(call_id: str, message: str) -> dict[str, Any]:
    return {
        "type": "tool_result",
        "tool_use_id": call_id,
        "content": message,
        "is_error": True,
    }


def _as_text(result: Any) -> str:
    if isinstance(result, str):
        return result
    import json

    try:
        return json.dumps(result)
    except (TypeError, ValueError):
        return repr(result)
