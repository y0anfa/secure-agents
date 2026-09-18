"""The lethal trifecta check.

An agent that can (1) reach private data, (2) ingest content an attacker may
have written, and (3) send bytes outside the trust boundary can be made to
exfiltrate. Not might: can. The injection does not have to be clever, because
the agent already holds every capability the attack needs.

All three legs are declared on the tools, so the combination is computable
before the agent runs. :class:`~secure_agents.agent.Agent` runs this check at
construction and refuses rather than warns. A warning in a log nobody reads is
not a control.

Three ways out, all of which the deployer states explicitly:

* Drop a leg. Two narrow agents usually beat one broad one.
* Gate the external leg. A policy that routes external calls to a human (or
  denies them) once the context is tainted breaks the chain, and is what the
  default taint escalation already does.
* Acknowledge the risk: ``acknowledge_exfiltration_risk="..."``. The reason
  goes in the audit log, and it is the first thing a reviewer will read.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .errors import SecureAgentsError
from .tools import EXTERNAL, PRIVATE, UNTRUSTED, ToolSpec


class SecurityConfigError(SecureAgentsError):
    """The agent as configured has a structural problem, found before it ran."""


@dataclass(frozen=True)
class Trifecta:
    """The tools supplying each leg."""

    private: tuple[str, ...]
    untrusted: tuple[str, ...]
    external: tuple[str, ...]

    @property
    def complete(self) -> bool:
        return bool(self.private and self.untrusted and self.external)

    def explain(self) -> str:
        return (
            f"reach private data ({', '.join(self.private)}), "
            f"ingest untrusted content ({', '.join(self.untrusted)}), "
            f"and communicate externally ({', '.join(self.external)})"
        )


def find_trifecta(specs: Sequence[ToolSpec]) -> Trifecta:
    """Which declared tools supply which leg."""
    return Trifecta(
        private=tuple(s.name for s in specs if PRIVATE in s.exposure),
        untrusted=tuple(s.name for s in specs if UNTRUSTED in s.exposure),
        external=tuple(
            s.name for s in specs if EXTERNAL in s.exposure or s.effect_class == "External"
        ),
    )


def check(
    specs: Sequence[ToolSpec],
    ungated_external: Sequence[str],
    acknowledged: str | None = None,
) -> Trifecta:
    """Raise :class:`SecurityConfigError` if the trifecta is complete and open.

    Args:
        specs: The agent's tools.
        ungated_external: Names of external-leg tools that the policy can still
            allow outright once the context is tainted. An external tool the
            policy escalates to ``ask`` or denies is not a live exfiltration
            channel, so it does not count.
        acknowledged: A deployer's reason for accepting the risk anyway.
    """
    trifecta = find_trifecta(specs)
    if not trifecta.complete or not ungated_external or acknowledged:
        return trifecta

    raise SecurityConfigError(
        "this agent can "
        + trifecta.explain()
        + ". An attacker who controls what "
        + trifecta.untrusted[0]
        + " returns can make it send "
        + trifecta.private[0]
        + "'s output to a destination of their choosing.\n"
        + "These external tools are not gated once the context is tainted: "
        + ", ".join(ungated_external)
        + ".\nResolve by one of:\n"
        "  - remove a leg: build two narrower agents instead of one broad one\n"
        "  - gate the external leg: drop the 'when_tainted=Decision.ALLOW' on "
        "those rules, or write policy.ask(...) for them, and pass an approver\n"
        "  - narrow the external tool's arguments, e.g. "
        "when=arg('to').in_(['ops@corp'])\n"
        "  - accept it on the record: "
        "Agent(..., acknowledge_exfiltration_risk='<why>')"
    )
