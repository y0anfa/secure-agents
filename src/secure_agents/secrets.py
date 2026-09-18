"""Secrets that tools can use but the model never sees.

Two separate problems, two mechanisms:

1. A secret must not reach the model's context on the way *in*. A
   :class:`Secret` is a handle. It is resolved to a value inside the sandbox,
   at call time, and passed to the tool out of band. It never appears in a
   prompt, a tool schema, or an argument.
2. A secret must not reach the model's context on the way *out*. Tools return
   text, and text has a habit of containing the token that was just used.
   :class:`Redactor` scrubs known secret values from tool results before they
   are appended to the conversation.

Neither is a guarantee against a tool that deliberately leaks. They remove the
accidents, which is most of them.
"""

from __future__ import annotations

import os
from collections.abc import Callable

from .errors import SecretError

_MIN_REDACTABLE_LEN = 6
"""Below this length, redaction does more harm than good: short values collide
with ordinary words and would shred unrelated output."""


class Secret:
    """A named secret, resolved lazily from the environment or a provider.

    >>> token = Secret("GITHUB_TOKEN")
    >>> repr(token)
    "Secret('GITHUB_TOKEN')"

    ``str(secret)`` raises rather than silently interpolating the value into a
    log line or an f-string. Call :meth:`reveal` to get the value, and keep
    that call as close to the use site as you can.
    """

    __slots__ = ("name", "_provider")

    def __init__(self, name: str, provider: Callable[[str], str | None] | None = None) -> None:
        self.name = name
        self._provider = provider or os.environ.get

    def reveal(self) -> str:
        value = self._provider(self.name)
        if value is None:
            raise SecretError(f"secret {self.name!r} is not set")
        return value

    def available(self) -> bool:
        return self._provider(self.name) is not None

    def __repr__(self) -> str:
        return f"Secret({self.name!r})"

    def __str__(self) -> str:
        raise SecretError(
            f"refusing to stringify secret {self.name!r}; call .reveal() if you mean it"
        )

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Secret) and other.name == self.name

    def __hash__(self) -> int:
        return hash(("Secret", self.name))


class Redactor:
    """Replaces known secret values with ``[redacted:NAME]``."""

    def __init__(self) -> None:
        self._values: dict[str, str] = {}

    def register(self, name: str, value: str) -> None:
        if value and len(value) >= _MIN_REDACTABLE_LEN:
            self._values[value] = f"[redacted:{name}]"

    def redact(self, text: str) -> str:
        if not self._values:
            return text
        # Longest first, so a secret that contains another is replaced whole.
        for value in sorted(self._values, key=len, reverse=True):
            if value in text:
                text = text.replace(value, self._values[value])
        return text

    def __len__(self) -> int:
        return len(self._values)
