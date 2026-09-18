"""Turning a Python function into a tool the model can call.

A tool is a function plus three pieces of metadata that the rest of the SDK
needs in order to reason about it:

``effects``
    What the tool does to the world. Policy rules are written against effects
    as much as names, so a new tool with ``effects="network"`` inherits the
    caution already expressed about network tools instead of being allowed by
    an overlooked wildcard.
``secrets``
    Which secrets the tool needs. They are resolved inside the sandbox and
    passed as a ``secrets`` keyword argument, never through the model.
``timeout_s``
    How long it may run before the sandbox kills it.
``exposure``
    Which legs of the lethal trifecta this tool supplies: does it reach
    private data, does it return content an attacker may control, can it move
    bytes outside the trust boundary. An agent holding all three can be made
    to exfiltrate, so :class:`~secure_agents.agent.Agent` refuses to construct
    one. See :mod:`secure_agents.trifecta`.

The JSON schema is derived from the signature and the docstring, so there is
one place to change when a tool changes.
"""

from __future__ import annotations

import inspect
import types
import typing
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, Union, get_args, get_origin

from .errors import SchemaError

READ = "read"
WRITE = "write"
NETWORK = "network"
EXEC = "exec"
SEND = "send"

EFFECTS = frozenset({READ, WRITE, NETWORK, EXEC, SEND})
"""The closed vocabulary of effects.

Closed on purpose: policy is only useful if the words in it mean the same
thing in every tool module. ``read`` observes local state, ``write`` changes
it, ``network`` talks to a remote host, ``exec`` runs code or a subprocess,
``send`` emits something a third party will see (mail, a message, a webhook)
and therefore cannot be undone.
"""

SIDE_EFFECTING = EFFECTS - {READ}

PRIVATE = "private"
UNTRUSTED = "untrusted"
EXTERNAL = "external"

EXPOSURES = frozenset({PRIVATE, UNTRUSTED, EXTERNAL})
"""The three legs of the lethal trifecta, declared per tool.

``private``
    The tool can reach data the principal would not want published: an inbox,
    a customer record, a private repository, a secret.
``untrusted``
    The tool returns content someone outside the trust boundary may have
    authored: a web page, an email, a ticket, another agent's output. Note
    that *every* tool result taints the context for provenance purposes; this
    flag is narrower and means "this is where attacker text gets in".
``external``
    The tool can move bytes outside the boundary. Derived from the ``send``
    and ``network`` effects unless you say otherwise, since those are already
    declarations rather than guesses.
"""


@dataclass(frozen=True)
class ToolSpec:
    """Everything about a tool except its body."""

    name: str
    description: str
    input_schema: dict[str, Any]
    effects: frozenset[str] = frozenset()
    secrets: tuple[str, ...] = ()
    timeout_s: float = 30.0
    exposure: frozenset[str] = frozenset()

    @property
    def side_effecting(self) -> bool:
        return bool(self.effects & SIDE_EFFECTING)

    @property
    def effect_class(self) -> str:
        """The tool in the threat model's four-value vocabulary.

        ``Pure`` (nothing), ``Read`` (inside the boundary), ``Write`` (mutates
        what the principal owns), ``External`` (leaves the boundary). Derived
        from the declared effects, so there is one place to change.
        """
        if self.effects & {SEND, NETWORK} or EXTERNAL in self.exposure:
            return "External"
        if self.effects & {WRITE, EXEC}:
            return "Write"
        if READ in self.effects:
            return "Read"
        return "Pure"

    def wire(self, strict: bool = True) -> dict[str, Any]:
        """The tool as the Messages API wants it."""
        payload: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }
        if strict:
            payload["strict"] = True
        return payload


@dataclass(frozen=True)
class Tool:
    """A callable bound to its :class:`ToolSpec`."""

    spec: ToolSpec
    fn: Callable[..., Any]
    module: str
    qualname: str

    @property
    def name(self) -> str:
        return self.spec.name

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """Call the underlying function directly.

        This bypasses policy and the sandbox. It exists so tools stay
        unit-testable as ordinary functions; the agent never uses it.
        """
        return self.fn(*args, **kwargs)


def tool(
    fn: Callable[..., Any] | None = None,
    *,
    name: str | None = None,
    effects: str | typing.Iterable[str] = (),
    secrets: typing.Iterable[str] = (),
    timeout_s: float = 30.0,
    exposure: str | typing.Iterable[str] = (),
) -> Any:
    """Decorator that registers a function as a tool.

    >>> @tool(effects="read", exposure="private")
    ... def read_note(path: str) -> str:
    ...     '''Read a note from disk.
    ...
    ...     Args:
    ...         path: Absolute path to the note.
    ...     '''
    ...     return open(path).read()
    """

    def decorate(func: Callable[..., Any]) -> Tool:
        declared = {effects} if isinstance(effects, str) else set(effects)
        declared.discard("")
        unknown = declared - EFFECTS
        if unknown:
            raise SchemaError(
                f"tool {func.__name__!r} declares unknown effects {sorted(unknown)}; "
                f"valid effects are {sorted(EFFECTS)}"
            )
        declared_exposure = {exposure} if isinstance(exposure, str) else set(exposure)
        declared_exposure.discard("")
        unknown_exposure = declared_exposure - EXPOSURES
        if unknown_exposure:
            raise SchemaError(
                f"tool {func.__name__!r} declares unknown exposure {sorted(unknown_exposure)}; "
                f"valid values are {sorted(EXPOSURES)}"
            )
        if declared & {SEND, NETWORK}:
            # Derived from another declaration, not guessed from the name.
            declared_exposure.add(EXTERNAL)

        summary, arg_docs = _parse_docstring(func)
        if not summary:
            raise SchemaError(
                f"tool {func.__name__!r} has no docstring; the model needs a "
                "description to use it correctly"
            )
        schema = build_schema(func, arg_docs)
        spec = ToolSpec(
            name=name or func.__name__,
            description=summary,
            input_schema=schema,
            effects=frozenset(declared),
            secrets=tuple(secrets),
            timeout_s=timeout_s,
            exposure=frozenset(declared_exposure),
        )
        return Tool(spec=spec, fn=func, module=func.__module__, qualname=func.__qualname__)

    if fn is not None:
        return decorate(fn)
    return decorate


# --------------------------------------------------------------------------
# Schema generation
# --------------------------------------------------------------------------

_SIMPLE = {str: "string", int: "integer", float: "number", bool: "boolean"}

RESERVED_PARAMS = frozenset({"secrets"})
"""Parameter names the sandbox fills in, excluded from the model's schema."""


def build_schema(
    func: Callable[..., Any], arg_docs: dict[str, str] | None = None
) -> dict[str, Any]:
    """Derive a strict JSON schema from a function signature.

    ``additionalProperties`` is always false. The model cannot invent a
    parameter that the function happens to accept via ``**kwargs``, and the
    schema is accepted by the Messages API in strict mode.
    """
    arg_docs = arg_docs or {}
    signature = inspect.signature(func)
    try:
        hints = typing.get_type_hints(func)
    except Exception as exc:  # pragma: no cover - exotic annotations
        raise SchemaError(f"cannot resolve type hints for {func.__name__!r}: {exc}") from exc

    properties: dict[str, Any] = {}
    required: list[str] = []
    for param_name, param in signature.parameters.items():
        if param_name in RESERVED_PARAMS:
            continue
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            raise SchemaError(
                f"tool {func.__name__!r} uses *args/**kwargs; tools need an "
                "explicit signature so the schema can be checked"
            )
        if param_name not in hints:
            raise SchemaError(
                f"parameter {param_name!r} of {func.__name__!r} has no type annotation"
            )
        properties[param_name] = _schema_for(hints[param_name], func.__name__, param_name)
        if param_name in arg_docs:
            properties[param_name]["description"] = arg_docs[param_name]
        if param.default is inspect.Parameter.empty:
            required.append(param_name)

    return {
        "type": "object",
        "properties": properties,
        "required": required,
        "additionalProperties": False,
    }


def _schema_for(annotation: Any, tool_name: str, param_name: str) -> dict[str, Any]:
    if annotation in _SIMPLE:
        return {"type": _SIMPLE[annotation]}

    origin = get_origin(annotation)
    args = get_args(annotation)

    if origin is Literal:
        if not all(isinstance(a, (str, int, bool)) for a in args):
            raise SchemaError(f"{tool_name}.{param_name}: Literal values must be str/int/bool")
        kind = "string" if isinstance(args[0], str) else "integer"
        return {"type": kind, "enum": list(args)}

    # Both spellings of a union: typing.Optional[X] and the PEP 604 X | None.
    if origin is Union or origin is types.UnionType:
        non_none = [a for a in args if a is not type(None)]
        if len(non_none) != 1:
            raise SchemaError(
                f"{tool_name}.{param_name}: only Optional[X] unions are supported, got {annotation}"
            )
        # Optional is expressed by omission (the parameter is not required),
        # not by a nullable type: strict mode rejects union types.
        return _schema_for(non_none[0], tool_name, param_name)

    if origin in (list, tuple):
        item = args[0] if args else str
        return {"type": "array", "items": _schema_for(item, tool_name, param_name)}

    if origin is dict:
        return {"type": "object", "additionalProperties": True}

    if annotation in (list, dict):
        return {"type": "array"} if annotation is list else {"type": "object"}

    raise SchemaError(
        f"{tool_name}.{param_name}: unsupported annotation {annotation!r}. "
        "Tools take str, int, float, bool, Literal, Optional, list[...] or dict."
    )


def _parse_docstring(func: Callable[..., Any]) -> tuple[str, dict[str, str]]:
    """Split a Google-style docstring into a summary and per-argument docs."""
    doc = inspect.getdoc(func) or ""
    if not doc.strip():
        return "", {}

    lines = doc.splitlines()
    summary_lines: list[str] = []
    arg_docs: dict[str, str] = {}
    in_args = False
    current: str | None = None

    for line in lines:
        stripped = line.strip()
        if stripped.lower() in ("args:", "arguments:", "parameters:"):
            in_args = True
            continue
        if in_args and stripped and not line.startswith((" ", "\t")):
            in_args = False
        if in_args:
            if ":" in stripped and not stripped.startswith(" "):
                key, _, rest = stripped.partition(":")
                stripped_key = key.strip()
                current = stripped_key.split()[0] if stripped_key else None
                if current:
                    arg_docs[current] = rest.strip()
            elif current and stripped:
                arg_docs[current] = (arg_docs.get(current, "") + " " + stripped).strip()
        else:
            summary_lines.append(stripped)

    summary = " ".join(part for part in summary_lines if part).strip()
    return summary, arg_docs


# --------------------------------------------------------------------------
# Argument validation
# --------------------------------------------------------------------------

_CHECKS: dict[str, Callable[[Any], bool]] = {
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "number": lambda v: isinstance(v, (int, float)) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "array": lambda v: isinstance(v, list),
    "object": lambda v: isinstance(v, dict),
}


def validate_args(schema: dict[str, Any], args: dict[str, Any]) -> None:
    """Check ``args`` against ``schema``, raising :class:`SchemaError`.

    Deliberately small: the schemas this SDK generates are a narrow subset of
    JSON Schema, and a dependency-free checker that covers exactly that subset
    is easier to audit than a general one. It runs before policy, so a
    malformed call is rejected before any rule has to reason about it.
    """
    if not isinstance(args, dict):
        raise SchemaError(f"arguments must be an object, got {type(args).__name__}")

    properties = schema.get("properties", {})
    unexpected = set(args) - set(properties)
    if unexpected:
        raise SchemaError(f"unexpected argument(s): {', '.join(sorted(unexpected))}")

    missing = [name for name in schema.get("required", []) if name not in args]
    if missing:
        raise SchemaError(f"missing required argument(s): {', '.join(missing)}")

    for key, value in args.items():
        _validate_value(key, value, properties[key])


def _validate_value(key: str, value: Any, spec: dict[str, Any]) -> None:
    expected = str(spec.get("type", ""))
    check = _CHECKS.get(expected)
    if check and not check(value):
        raise SchemaError(f"argument {key!r} should be {expected}, got {type(value).__name__}")
    if "enum" in spec and value not in spec["enum"]:
        raise SchemaError(f"argument {key!r} must be one of {spec['enum']}, got {value!r}")
    if expected == "array" and "items" in spec:
        for index, item in enumerate(value):
            _validate_value(f"{key}[{index}]", item, spec["items"])
