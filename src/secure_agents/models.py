"""The model behind the agent.

:class:`Model` is a one-method protocol. The SDK does not depend on any
provider package; :class:`AnthropicModel` imports ``anthropic`` lazily, and
:class:`ScriptedModel` lets the whole loop, policy and all, be tested without
a network call or an API key.

Messages are Anthropic-shaped dicts. That is the shape the tool-use protocol
is defined in, and inventing a second one would only mean translating twice.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from .errors import ModelRefusal
from .tools import ToolSpec

DEFAULT_MODEL = "claude-opus-5"
DEFAULT_MAX_TOKENS = 16000
FALLBACK_BETA = "server-side-fallback-2026-07-01"


@dataclass(frozen=True)
class ToolUse:
    """One tool call the model asked for."""

    id: str
    name: str
    args: dict[str, Any]


@dataclass(frozen=True)
class ModelResponse:
    text: str
    tool_uses: tuple[ToolUse, ...] = ()
    stop_reason: str | None = None
    content_blocks: Any = field(default=())
    """What to append back as the assistant turn. Passed through untouched so
    provider-specific blocks (thinking, citations) survive the round trip."""

    usage: dict[str, Any] | None = None


class Model(Protocol):
    def complete(
        self,
        *,
        system: str | None,
        messages: list[dict[str, Any]],
        tools: Sequence[ToolSpec],
    ) -> ModelResponse: ...

    def describe(self) -> str: ...


# --------------------------------------------------------------------------


class ScriptedModel:
    """A model that replays a fixed script. For tests and examples.

    Each turn is either a string (the model's final answer) or a list of
    ``(tool_name, args)`` pairs (the tools it wants to call):

    >>> ScriptedModel([
    ...     [("read_file", {"path": "/srv/data/a.txt"})],
    ...     "The file says hello.",
    ... ])
    """

    def __init__(self, script: Sequence[Any], name: str = "scripted") -> None:
        self.script = list(script)
        self.name = name
        self.calls: list[dict[str, Any]] = []
        self._turn = 0

    def describe(self) -> str:
        return f"scripted model ({len(self.script)} turns)"

    def complete(
        self,
        *,
        system: str | None,
        messages: list[dict[str, Any]],
        tools: Sequence[ToolSpec],
    ) -> ModelResponse:
        self.calls.append({"system": system, "messages": list(messages), "tools": list(tools)})
        if self._turn >= len(self.script):
            return ModelResponse(text="", stop_reason="end_turn", content_blocks=[])
        turn = self.script[self._turn]
        self._turn += 1

        if isinstance(turn, str):
            return ModelResponse(
                text=turn,
                stop_reason="end_turn",
                content_blocks=[{"type": "text", "text": turn}],
            )

        uses = []
        blocks: list[dict[str, Any]] = []
        for index, item in enumerate(turn):
            name, args = item
            use = ToolUse(id=f"call_{self._turn}_{index}", name=name, args=dict(args))
            uses.append(use)
            blocks.append({"type": "tool_use", "id": use.id, "name": use.name, "input": use.args})
        return ModelResponse(
            text="", tool_uses=tuple(uses), stop_reason="tool_use", content_blocks=blocks
        )


# --------------------------------------------------------------------------


class AnthropicModel:
    """The Claude Messages API, wired to the agent loop.

    The loop lives in :class:`~secure_agents.agent.Agent` rather than in the
    SDK's tool runner, because the policy check has to sit between "the model
    asked" and "the tool ran", and it has to be able to refuse. That is the
    whole point of this library, so the loop is ours.

    Args:
        model: Model id. Defaults to ``claude-opus-5``.
        max_tokens: Output cap.
        client: An ``anthropic.Anthropic`` instance. Constructed from the
            environment if omitted.
        effort: ``"low"`` to ``"max"``. Left unset (the API default is
            ``high``) unless you have measured that you need another level.
        thinking: ``"adaptive"`` by default.
        strict_tools: Send ``strict: true`` with each tool, so tool arguments
            are guaranteed to validate against the schema. Worth keeping on:
            it removes a class of malformed call before policy has to reason
            about it.
        fallbacks: Server-side refusal fallback. ``"default"`` lets the API
            route a refused request to another model by category; pass ``None``
            to turn it off and get :class:`ModelRefusal` instead. Note that
            this changes which model answers, so in a regulated setting you may
            want it off and the refusal surfaced.
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        client: Any = None,
        effort: str | None = None,
        thinking: str | None = "adaptive",
        strict_tools: bool = True,
        fallbacks: Any = "default",
        extra_params: dict[str, Any] | None = None,
    ) -> None:
        if client is None:
            try:
                import anthropic  # type: ignore[import-not-found]
            except ImportError as exc:  # pragma: no cover - depends on install extras
                raise ImportError(
                    "AnthropicModel needs the anthropic package: "
                    "pip install 'secure-agents[anthropic]'"
                ) from exc
            client = anthropic.Anthropic()
        self.client = client
        self.model = model
        self.max_tokens = max_tokens
        self.effort = effort
        self.thinking = thinking
        self.strict_tools = strict_tools
        self.fallbacks = fallbacks
        self.extra_params = extra_params or {}

    def describe(self) -> str:
        return f"anthropic:{self.model}"

    def complete(
        self,
        *,
        system: str | None,
        messages: list[dict[str, Any]],
        tools: Sequence[ToolSpec],
    ) -> ModelResponse:
        params: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": messages,
            "tools": [spec.wire(strict=self.strict_tools) for spec in tools],
            **self.extra_params,
        }
        if system:
            params["system"] = system
        if self.thinking:
            params["thinking"] = {"type": self.thinking}
        if self.effort:
            params["output_config"] = {"effort": self.effort}

        if self.fallbacks:
            response = self.client.beta.messages.create(
                betas=[FALLBACK_BETA], fallbacks=self.fallbacks, **params
            )
        else:
            response = self.client.messages.create(**params)

        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            raise ModelRefusal(
                getattr(details, "category", None), getattr(details, "explanation", None)
            )

        text_parts: list[str] = []
        uses: list[ToolUse] = []
        for block in response.content:
            kind = getattr(block, "type", None)
            if kind == "text":
                text_parts.append(block.text)
            elif kind == "tool_use":
                uses.append(ToolUse(id=block.id, name=block.name, args=dict(block.input)))

        usage = getattr(response, "usage", None)
        usage_dict = None
        if usage is not None and hasattr(usage, "model_dump"):
            usage_dict = usage.model_dump()
        return ModelResponse(
            text="".join(text_parts),
            tool_uses=tuple(uses),
            stop_reason=response.stop_reason,
            content_blocks=response.content,
            usage=usage_dict,
        )
