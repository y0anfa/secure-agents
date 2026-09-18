"""What this example claims, as assertions."""

from ops import SCRIPT, build_agent

from secure_agents import Decision, JsonlAudit, ScriptedModel, deny_all_approver, verify_chain


def run(approver, audit=None):
    agent = build_agent(ScriptedModel(SCRIPT), approver=approver, audit=audit)
    return agent.run("Prod looks unhealthy. Sort it out.")


def find(result, name):
    return next(r for r in result.calls if r.call.name == name)


def test_unattended_the_irreversible_call_is_declined():
    result = run(deny_all_approver)
    terminate = find(result, "terminate_instance")
    assert terminate.verdict.decision is Decision.ASK
    assert terminate.approved is False
    assert not terminate.ran


def test_unattended_the_rest_of_the_work_still_happens():
    # Declining one call must not abort the run.
    result = run(deny_all_approver)
    assert find(result, "list_instances").ran
    assert find(result, "restart_instance").ran
    assert result.text


def test_a_restart_does_not_ask_because_the_policy_says_so_explicitly():
    result = run(deny_all_approver)
    restart = find(result, "restart_instance")
    assert restart.verdict.decision is Decision.ALLOW
    assert not restart.verdict.escalated


def test_with_an_approver_the_terminate_proceeds():
    result = run(lambda call, verdict: True)
    terminate = find(result, "terminate_instance")
    assert terminate.approved is True
    assert terminate.ran


def test_the_approval_is_in_the_audit_log(tmp_path):
    path = tmp_path / "audit.jsonl"
    run(lambda call, verdict: True, audit=JsonlAudit(path))
    body = path.read_text(encoding="utf-8")
    assert '"approval.resolved"' in body
    assert '"approved": true' in body
    assert verify_chain(path) == (True, None)


def test_deleting_a_line_from_the_log_is_detectable(tmp_path):
    path = tmp_path / "audit.jsonl"
    run(lambda call, verdict: True, audit=JsonlAudit(path))
    lines = path.read_text(encoding="utf-8").splitlines()
    kept = [ln for ln in lines if '"approval.resolved"' not in ln]
    assert len(kept) < len(lines)
    path.write_text("\n".join(kept) + "\n", encoding="utf-8")

    intact, bad_line = verify_chain(path)
    assert intact is False
    assert bad_line is not None
