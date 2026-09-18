"""What this example claims, as assertions."""

import pytest
from assistant import SCRIPT, build_agent
from repo_tools import ensure_fixtures

from secure_agents import Decision, MemoryAudit, ScriptedModel, deny_all_approver


@pytest.fixture(scope="module")
def result():
    ensure_fixtures()
    agent = build_agent(ScriptedModel(SCRIPT), approver=deny_all_approver, audit=MemoryAudit())
    return agent.run("Have a look at calc.py and run the checks.")


def by_arg(result, tool_name, needle):
    return [r for r in result.calls if r.call.name == tool_name and needle in str(r.call.args)]


def test_a_file_inside_the_checkout_is_readable(result):
    ok = by_arg(result, "read_file", "calc.py")
    assert len(ok) == 1
    assert ok[0].verdict.decision is Decision.ALLOW
    assert ok[0].ran


def test_path_traversal_out_of_the_checkout_is_denied(result):
    denied = by_arg(result, "read_file", "id_rsa")
    assert len(denied) == 1
    assert denied[0].verdict.decision is Decision.DENY
    assert not denied[0].ran


def test_a_symlink_pointing_out_of_the_checkout_is_denied(result):
    # The path string starts with the workspace prefix. A naive
    # startswith() check would let this through; under() resolves it first.
    if not ensure_fixtures():
        pytest.skip("this filesystem has no symlinks")
    denied = by_arg(result, "read_file", "notes.txt")
    assert len(denied) == 1
    assert denied[0].verdict.decision is Decision.DENY


def test_the_secret_outside_the_checkout_was_never_read(result):
    # The real assertion: not just "denied", but that the bytes never moved.
    for record in result.calls:
        assert "AKIA-not-a-real-key" not in str(record.result or "")


def test_a_command_off_the_allowlist_is_denied(result):
    denied = by_arg(result, "run_command", "curl")
    assert len(denied) == 1
    assert denied[0].verdict.decision is Decision.DENY


def test_a_command_on_the_allowlist_still_asks_once_tainted(result):
    listed = by_arg(result, "run_command", "compileall")
    assert len(listed) == 1
    assert listed[0].verdict.decision is Decision.ASK
    assert listed[0].verdict.escalated
