"""Where the bytes in the context came from.

Prompt injection is not a model bug you can patch, it is a consequence of
mixing instructions and data in one channel. secure-agents does not try to
detect injected instructions. It tracks *provenance* instead: every piece of
content that enters the conversation is labelled with how much it is trusted,
and policy gets to see that label when it decides whether a tool call runs.

The rule that falls out of this is simple and checkable: once untrusted
content is in the context, effectful tool calls are no longer routine.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Trust(str, Enum):
    """How much the content from a source is trusted."""

    TRUSTED = "trusted"
    """Authored by the developer: the system prompt, constants in the code."""

    USER = "user"
    """Typed by the human principal the agent is acting for."""

    UNTRUSTED = "untrusted"
    """Everything the agent read rather than was told: tool output, fetched
    pages, file contents, other agents. Content here may be adversarial."""


@dataclass(frozen=True, order=True)
class Source:
    """One contributor of content to the conversation."""

    trust: Trust
    label: str
    """Human-readable origin, e.g. ``"tool:read_file"`` or ``"user"``."""

    def __str__(self) -> str:  # pragma: no cover - display only
        return f"{self.label}({self.trust.value})"


@dataclass(frozen=True)
class Provenance:
    """The set of sources that have contributed to a context, in order."""

    sources: tuple[Source, ...] = ()

    @classmethod
    def from_user(cls, label: str = "user") -> Provenance:
        return cls((Source(Trust.USER, label),))

    def with_source(self, source: Source) -> Provenance:
        """Return a new Provenance with ``source`` added (deduplicated)."""
        if source in self.sources:
            return self
        return Provenance(self.sources + (source,))

    @property
    def tainted(self) -> bool:
        """True once any untrusted content has entered the context."""
        return any(s.trust is Trust.UNTRUSTED for s in self.sources)

    @property
    def untrusted_labels(self) -> tuple[str, ...]:
        return tuple(s.label for s in self.sources if s.trust is Trust.UNTRUSTED)

    def describe(self) -> str:
        if not self.tainted:
            return "untainted"
        return "tainted by " + ", ".join(self.untrusted_labels)
