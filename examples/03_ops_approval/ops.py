"""An ops agent that can do something irreversible, and the paper trail.

Two things a security team needs before an agent touches production, neither
of which is about stopping the model:

* **A human in the loop on the calls that matter.** ``policy.ask`` routes a
  call to an approver. Unattended, ``deny_all_approver`` declines it and the
  run continues without that step, which is the right failure mode for a
  cron job: the agent still does the nine things that were fine.
* **A record that survives the agent.** ``JsonlAudit`` hash-chains its
  entries, so a line that was edited or removed afterwards is detectable.
  That is tamper evidence, not tamper proofing. It is worth having because
  the question after an incident is never "what did the model say", it is
  "what did it actually do, and who said yes".

The agent's own credentials should not be able to write to wherever this log
ends up. Ship it off the box.
"""

from __future__ import annotations

from pathlib import Path

from ops_tools import list_instances, restart_instance, terminate_instance

from secure_agents import (
    Agent,
    Decision,
    JsonlAudit,
    Policy,
    ScriptedModel,
    arg,
    deny_all_approver,
    verify_chain,
)
from secure_agents.sandbox import Egress, Subprocess

AUDIT_PATH = Path(__file__).parent / "audit.jsonl"
INSTANCE_ID = r"i-[0-9a-f]{8}"


def build_policy() -> Policy:
    return (
        Policy.default_deny()
        .allow("list_instances", name="read the fleet")
        .allow(
            "restart_instance",
            when=arg("instance_id").matches(INSTANCE_ID),
            # Without this, reading the fleet list would taint the context and
            # every restart would need a human, which is how an agent becomes
            # more annoying than useful. Overriding the escalation is a
            # deliberate, greppable line rather than a default nobody chose.
            when_tainted=Decision.ALLOW,
            name="restart",
            reason="a restart is recoverable",
        )
        .ask(
            "terminate_instance",
            when=arg("instance_id").matches(INSTANCE_ID),
            name="terminate needs a human",
            reason="terminating an instance cannot be undone",
        )
    )


def build_agent(model, approver, audit=None):
    return Agent(
        model=model,
        tools=[list_instances, restart_instance, terminate_instance],
        policy=build_policy(),
        sandbox=Subprocess(egress=Egress.deny_all()),
        approver=approver,
        audit=audit,
        system="You keep the fleet healthy. Prefer a restart over a terminate.",
    )


SCRIPT = [
    [("list_instances", {"environment": "prod"})],
    [("restart_instance", {"instance_id": "i-4a1b2c3d"})],
    [("terminate_instance", {"instance_id": "i-9f8e7d6c"})],
    "Restarted the api box. The worker needs terminating but I could not do that myself.",
]


def approve_everything(call, verdict) -> bool:
    print(f"  [approver] yes to {call.name}({call.args}) because: {verdict.reason}")
    return True


def run_once(approver, label):
    print(f"\n=== {label} ===")
    audit = JsonlAudit(AUDIT_PATH)
    agent = build_agent(ScriptedModel(SCRIPT), approver=approver, audit=audit)
    result = agent.run("Prod looks unhealthy. Sort it out.")
    for record in result.calls:
        mark = "ok  " if record.ran else "STOP"
        print(f"  {mark} {record.call.name:<20} {record.verdict.decision.value}")
        if record.approved is False:
            print(f"       declined by a human: {record.verdict.reason}")
    return result


def main() -> int:
    AUDIT_PATH.unlink(missing_ok=True)

    run_once(deny_all_approver, "unattended: nobody is there to say yes")
    run_once(approve_everything, "attended: a human approves the terminate")

    print("\n=== the audit trail ===")
    lines = AUDIT_PATH.read_text(encoding="utf-8").splitlines()
    print(f"  {len(lines)} events in {AUDIT_PATH.name}")
    intact, bad_line = verify_chain(AUDIT_PATH)
    print(f"  chain intact: {intact}")

    # Now quietly remove the evidence of the approval, the way someone would.
    kept = [ln for ln in lines if '"approval.resolved"' not in ln]
    AUDIT_PATH.write_text("\n".join(kept) + "\n", encoding="utf-8")
    intact, bad_line = verify_chain(AUDIT_PATH)
    print(f"  after deleting the approval records, intact: {intact} (bad line: {bad_line})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
