"""The security claims this example makes, as assertions.

If a change to the SDK lets the exfiltration through, this fails. That is the
point of testing the examples: the README says the attack is stopped, and CI
is what keeps that sentence true.
"""

from inbox_tools import read_message, send_email
from triage import INJECTED_SCRIPT, build_agent, build_policy

from secure_agents import Decision, MemoryAudit, ScriptedModel, deny_all_approver
from secure_agents.trifecta import check, find_trifecta


def run_injected():
    audit = MemoryAudit()
    agent = build_agent(ScriptedModel(INJECTED_SCRIPT), approver=deny_all_approver, audit=audit)
    return agent.run("Triage the inbox and send the team a summary."), audit


def test_the_injection_is_actually_in_the_fixture():
    # A demo where the attack is only described is not a demo.
    body = read_message("msg-002")
    assert "evil-collector.example" in body
    assert "send_email" in body


def test_exfiltration_to_the_attacker_is_denied():
    result, _ = run_injected()
    exfil = [
        r
        for r in result.calls
        if r.call.name == "send_email" and r.call.args["to"] == "archive@evil-collector.example"
    ]
    assert len(exfil) == 1
    assert exfil[0].verdict.decision is Decision.DENY
    assert not exfil[0].ran


def test_sending_to_an_allowed_address_still_asks_a_human_once_tainted():
    result, _ = run_injected()
    legit = [
        r
        for r in result.calls
        if r.call.name == "send_email" and r.call.args["to"] == "ops@corp.example"
    ]
    assert len(legit) == 1
    verdict = legit[0].verdict
    assert verdict.decision is Decision.ASK
    assert verdict.escalated, "taint should have escalated allow to ask"
    assert "tainted" in verdict.reason


def test_the_agent_still_does_its_job():
    # Denying the attack must not mean denying the work. An SDK that only
    # ever says no gets uninstalled.
    result, _ = run_injected()
    reads = [r for r in result.calls if r.call.name == "read_message"]
    assert len(reads) == 2
    assert all(r.ran for r in reads)
    assert result.text


def test_every_denial_is_in_the_audit_log():
    result, audit = run_injected()
    denied = {e.data["tool"] for e in audit.of_type("call.denied")}
    assert denied == {"send_email"}
    decisions = [e.data["decision"] for e in audit.of_type("policy.decision")]
    assert decisions == ["allow", "allow", "deny", "ask"]


def test_this_agent_holds_all_three_legs_of_the_trifecta():
    # It does, and that is why the policy has to gate the external leg.
    specs = [read_message.spec, send_email.spec]
    trifecta = find_trifecta(specs)
    assert trifecta.complete
    # Nothing is ungated: send_email escalates to ask once tainted, so the
    # construction check passes rather than refusing to build the agent.
    check(specs, ungated_external=[])
    assert build_policy().may_ask(specs)
