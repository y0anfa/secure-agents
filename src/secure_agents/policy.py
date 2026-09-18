"""The decision layer: what is this agent allowed to do, and when.

Every tool call the model asks for passes through a :class:`Policy` before it
runs. A policy is an ordered list of rules over tool names, arguments, effects
and provenance, with a default at the end. The default is deny.

Three things make this more than a name allowlist:

* **Argument predicates.** ``allow("read_file", when=arg("path").under("/srv/data"))``
  is a different, much narrower grant than ``allow("read_file")``.
* **Taint escalation.** A rule can say what it decides normally and what it
  decides once untrusted content is in the context. Side-effecting tools
  escalate to ``ASK`` by default, which is the control that makes a prompt
  injection cost an attacker a human click rather than nothing.
* **Config form.** :meth:`Policy.from_dict` loads the same policy from data,
  so it can live in a reviewed file rather than in code someone has to read.
"""

from __future__ import annotations

import fnmatch
import os
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from .provenance import Provenance
from .tools import ToolSpec


class Decision(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


@dataclass(frozen=True)
class ToolCall:
    """A tool call the model has asked for, before it runs."""

    id: str
    name: str
    args: dict[str, Any]
    provenance: Provenance
    step: int = 0

    def arg(self, name: str, default: Any = None) -> Any:
        return self.args.get(name, default)


@dataclass(frozen=True)
class Verdict:
    decision: Decision
    reason: str
    rule: str | None = None
    escalated: bool = False
    """True when taint changed the decision this rule would otherwise have made."""

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW


Predicate = Callable[[ToolCall], bool]


@dataclass(frozen=True)
class Rule:
    """One line of a policy."""

    tools: str
    """A glob over tool names: ``"read_file"``, ``"read_*"``, ``"*"``."""

    decision: Decision
    when: Predicate | None = None
    when_tainted: Decision | None = None
    """What to decide once untrusted content is in the context. ``None`` means
    "use the default escalation": side-effecting tools become ``ASK``,
    read-only tools keep their decision."""

    effects: frozenset[str] = frozenset()
    """If set, the rule only matches tools declaring at least one of these."""

    reason: str = ""
    name: str = ""

    def matches(self, call: ToolCall, spec: ToolSpec) -> bool:
        if not fnmatch.fnmatchcase(call.name, self.tools):
            return False
        if self.effects and not (self.effects & spec.effects):
            return False
        if self.when is not None and not self.when(call):
            return False
        return True

    def could_match(self, spec: ToolSpec) -> bool:
        """True if this rule could match some call to ``spec``.

        Arguments are unknown here, so a rule with a predicate counts as
        "could". Used by the static checks, which must over-approximate what a
        rule permits rather than under-approximate it.
        """
        if not fnmatch.fnmatchcase(spec.name, self.tools):
            return False
        return not (self.effects and not (self.effects & spec.effects))

    def decision_when_tainted(self, spec: ToolSpec) -> Decision:
        if self.when_tainted is not None:
            return self.when_tainted
        if self.decision is Decision.ALLOW and spec.side_effecting:
            return Decision.ASK
        return self.decision

    def resolve(self, call: ToolCall, spec: ToolSpec) -> Verdict:
        label = self.name or f"{self.decision.value} {self.tools}"
        reason = self.reason or f"matched rule {label!r}"
        if not call.provenance.tainted:
            return Verdict(self.decision, reason, label)

        tainted_decision = self.when_tainted
        if tainted_decision is None:
            tainted_decision = (
                Decision.ASK
                if self.decision is Decision.ALLOW and spec.side_effecting
                else self.decision
            )
        if tainted_decision is self.decision:
            return Verdict(self.decision, reason, label)
        return Verdict(
            tainted_decision,
            f"{reason}; escalated from {self.decision.value} because context is "
            f"{call.provenance.describe()}",
            label,
            escalated=True,
        )


class Policy:
    """An ordered rule list with a default. First match wins."""

    def __init__(
        self,
        rules: Sequence[Rule] = (),
        default: Decision = Decision.DENY,
        default_reason: str = "no rule matched and the default is deny",
    ) -> None:
        self.rules: list[Rule] = list(rules)
        self.default = default
        self.default_reason = default_reason

    # -- construction ------------------------------------------------------

    @classmethod
    def default_deny(cls) -> Policy:
        """An empty policy that denies everything. The place to start."""
        return cls()

    def allow(
        self,
        tools: str,
        *,
        when: Predicate | None = None,
        when_tainted: Decision | None = None,
        effects: Iterable[str] = (),
        reason: str = "",
        name: str = "",
    ) -> Policy:
        return self._add(Decision.ALLOW, tools, when, when_tainted, effects, reason, name)

    def ask(
        self,
        tools: str,
        *,
        when: Predicate | None = None,
        effects: Iterable[str] = (),
        reason: str = "",
        name: str = "",
    ) -> Policy:
        return self._add(Decision.ASK, tools, when, Decision.ASK, effects, reason, name)

    def deny(
        self,
        tools: str,
        *,
        when: Predicate | None = None,
        effects: Iterable[str] = (),
        reason: str = "",
        name: str = "",
    ) -> Policy:
        return self._add(Decision.DENY, tools, when, Decision.DENY, effects, reason, name)

    def _add(
        self,
        decision: Decision,
        tools: str,
        when: Predicate | None,
        when_tainted: Decision | None,
        effects: Iterable[str],
        reason: str,
        name: str,
    ) -> Policy:
        self.rules.append(
            Rule(
                tools=tools,
                decision=decision,
                when=when,
                when_tainted=when_tainted,
                effects=frozenset(effects),
                reason=reason,
                name=name,
            )
        )
        return self

    # -- use ---------------------------------------------------------------

    def decide(self, call: ToolCall, spec: ToolSpec) -> Verdict:
        for rule in self.rules:
            try:
                matched = rule.matches(call, spec)
            except Exception as exc:
                # Fail closed. A predicate that blows up is a policy the
                # deployer cannot reason about, so nothing runs.
                return Verdict(
                    Decision.DENY,
                    f"policy evaluation failed in rule {rule.name or rule.tools!r}: "
                    f"{type(exc).__name__}: {exc}",
                    rule=rule.name or None,
                )
            if matched:
                return rule.resolve(call, spec)
        return Verdict(self.default, self.default_reason, rule=None)

    def can_allow_when_tainted(self, spec: ToolSpec) -> bool:
        """Could a call to ``spec`` still be allowed outright once the context
        is tainted?

        Over-approximates: a rule with an argument predicate counts as one that
        could match, because the arguments are not known until the model picks
        them. Used by the trifecta check, where guessing wrong in the
        permissive direction would be the expensive mistake.
        """
        for rule in self.rules:
            if not rule.could_match(spec):
                continue
            if rule.decision_when_tainted(spec) is Decision.ALLOW:
                return True
            if rule.when is None:
                # Matches unconditionally, so no later rule is ever reached.
                return False
        return self.default is Decision.ALLOW

    def may_ask(self, specs: Iterable[ToolSpec] = ()) -> bool:
        """True if any rule can route a call to a human.

        The agent checks this at construction against its own tools: a policy
        that can ask needs somewhere to ask, and finding that out at 3am
        mid-run is worse than finding it out at startup. Passing the tool
        specs makes the answer exact, since default taint escalation depends
        on whether a tool has side effects.
        """
        if self.default is Decision.ASK:
            return True
        specs = list(specs)
        for rule in self.rules:
            if rule.decision is Decision.ASK or rule.when_tainted is Decision.ASK:
                return True
            if rule.decision is Decision.ALLOW and rule.when_tainted is None:
                # Default escalation: ASK for side-effecting tools only.
                if not specs:
                    return True
                if any(
                    spec.side_effecting
                    and fnmatch.fnmatchcase(spec.name, rule.tools)
                    and (not rule.effects or rule.effects & spec.effects)
                    for spec in specs
                ):
                    return True
        return False

    def describe(self) -> str:
        """The policy as readable lines, for logs and review."""
        lines = []
        for rule in self.rules:
            bits = [rule.decision.value.upper(), rule.tools]
            if rule.effects:
                bits.append(f"effects={sorted(rule.effects)}")
            if rule.when is not None:
                bits.append(f"when={getattr(rule.when, 'description', 'predicate')}")
            if rule.when_tainted and rule.when_tainted is not rule.decision:
                bits.append(f"tainted->{rule.when_tainted.value}")
            lines.append("  " + " ".join(bits))
        lines.append(f"  DEFAULT {self.default.value.upper()}")
        return "\n".join(lines)

    # -- config form -------------------------------------------------------

    @classmethod
    def from_dict(cls, config: dict[str, Any]) -> Policy:
        """Load a policy from plain data (TOML, YAML, JSON, a dict).

        ::

            {
              "default": "deny",
              "rules": [
                {"tools": "read_*", "decision": "allow",
                 "when": {"arg": "path", "under": "/srv/data"}},
                {"tools": "*", "decision": "ask", "effects": ["send"]}
              ]
            }
        """
        default = Decision(config.get("default", "deny"))
        rules = []
        for index, raw in enumerate(config.get("rules", [])):
            when = _predicate_from_dict(raw["when"]) if raw.get("when") else None
            when_tainted = Decision(raw["when_tainted"]) if raw.get("when_tainted") else None
            rules.append(
                Rule(
                    tools=raw.get("tools", "*"),
                    decision=Decision(raw["decision"]),
                    when=when,
                    when_tainted=when_tainted,
                    effects=frozenset(raw.get("effects", ())),
                    reason=raw.get("reason", ""),
                    name=raw.get("name", f"rule[{index}]"),
                )
            )
        return cls(rules, default=default)


# --------------------------------------------------------------------------
# Predicates
# --------------------------------------------------------------------------


def _described(fn: Predicate, description: str) -> Predicate:
    fn.description = description  # type: ignore[attr-defined]
    return fn


class ArgPredicate:
    """Builder for predicates over a single argument.

    >>> arg("path").under("/srv/data")
    >>> arg("url").host_in({"api.github.com"})
    """

    def __init__(self, name: str) -> None:
        self.name = name

    def equals(self, value: Any) -> Predicate:
        return _described(lambda call: call.arg(self.name) == value, f"{self.name} == {value!r}")

    def in_(self, values: Iterable[Any]) -> Predicate:
        allowed = frozenset(values)
        return _described(
            lambda call: call.arg(self.name) in allowed, f"{self.name} in {sorted(allowed)}"
        )

    def matches(self, pattern: str) -> Predicate:
        compiled = re.compile(pattern)
        return _described(
            lambda call: (
                isinstance(call.arg(self.name), str)
                and compiled.fullmatch(call.arg(self.name)) is not None
            ),
            f"{self.name} matches /{pattern}/",
        )

    def max_len(self, limit: int) -> Predicate:
        return _described(
            lambda call: len(call.arg(self.name) or "") <= limit, f"len({self.name}) <= {limit}"
        )

    def under(self, root: str) -> Predicate:
        """The argument is a path inside ``root``.

        Symlinks are resolved before the comparison, so ``/srv/data/link ->
        /etc/shadow`` does not pass. This is a check on the string the model
        supplied; the sandbox is what stops a tool that ignores it.
        """
        resolved_root = os.path.realpath(root)

        def check(call: ToolCall) -> bool:
            value = call.arg(self.name)
            if not isinstance(value, str):
                return False
            candidate = os.path.realpath(value)
            return candidate == resolved_root or candidate.startswith(resolved_root + os.sep)

        return _described(check, f"{self.name} under {resolved_root}")

    def host_in(self, hosts: Iterable[str]) -> Predicate:
        """The argument is a URL whose host is in ``hosts``.

        A leading dot allows subdomains: ``".example.com"`` matches
        ``api.example.com`` but not ``notexample.com``.
        """
        allowed = tuple(h.lower() for h in hosts)

        def check(call: ToolCall) -> bool:
            value = call.arg(self.name)
            if not isinstance(value, str):
                return False
            host = (urlparse(value).hostname or "").lower()
            if not host:
                return False
            return any(host == h or (h.startswith(".") and host.endswith(h)) for h in allowed)

        return _described(check, f"{self.name} host in {list(allowed)}")


def arg(name: str) -> ArgPredicate:
    return ArgPredicate(name)


def tainted(call: ToolCall) -> bool:
    """True when untrusted content has entered the context."""
    return call.provenance.tainted


tainted = _described(tainted, "context is tainted")  # type: ignore[assignment]


def all_of(*predicates: Predicate) -> Predicate:
    return _described(
        lambda call: all(p(call) for p in predicates),
        " and ".join(getattr(p, "description", "?") for p in predicates),
    )


def any_of(*predicates: Predicate) -> Predicate:
    return _described(
        lambda call: any(p(call) for p in predicates),
        " or ".join(getattr(p, "description", "?") for p in predicates),
    )


def not_(predicate: Predicate) -> Predicate:
    return _described(
        lambda call: not predicate(call), f"not ({getattr(predicate, 'description', '?')})"
    )


_CONFIG_PREDICATES = ("under", "equals", "in", "matches", "host_in", "max_len")


def _predicate_from_dict(raw: dict[str, Any]) -> Predicate:
    name = raw.get("arg")
    if not name:
        raise ValueError("a 'when' clause needs an 'arg' key")
    builder = arg(name)
    for key in _CONFIG_PREDICATES:
        if key in raw:
            method = {"in": "in_", "host_in": "host_in"}.get(key, key)
            return getattr(builder, method)(raw[key])
    raise ValueError(
        f"'when' clause for {name!r} has no known test; expected one of {list(_CONFIG_PREDICATES)}"
    )
