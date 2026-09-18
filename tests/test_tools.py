from typing import Literal

import pytest

from secure_agents import SchemaError, tool
from secure_agents.tools import validate_args


def test_schema_is_derived_from_signature_and_docstring():
    @tool(effects="read")
    def lookup(host: str, port: int = 443, scheme: Literal["http", "https"] = "https") -> str:
        """Look up a service.

        Args:
            host: The hostname.
            port: TCP port.
        """
        return host

    schema = lookup.spec.input_schema
    assert lookup.spec.description == "Look up a service."
    assert schema["properties"]["host"] == {"type": "string", "description": "The hostname."}
    assert schema["properties"]["port"]["type"] == "integer"
    assert schema["properties"]["scheme"]["enum"] == ["http", "https"]
    assert schema["required"] == ["host"]
    # Strict mode on the Messages API needs this, and it stops the model
    # inventing a parameter the function happens to accept.
    assert schema["additionalProperties"] is False


def test_optional_is_expressed_by_omission_not_by_a_nullable_type():
    @tool
    def maybe(name: str | None = None) -> str:
        """Takes an optional name."""
        return name or ""

    assert maybe.spec.input_schema["properties"]["name"] == {"type": "string"}
    assert maybe.spec.input_schema["required"] == []


def test_secrets_parameter_is_not_in_the_model_facing_schema():
    @tool(effects="network", secrets=["TOKEN"])
    def call_api(path: str, secrets: dict) -> str:
        """Call the API.

        Args:
            path: Request path.
        """
        return path

    assert "secrets" not in call_api.spec.input_schema["properties"]
    assert call_api.spec.secrets == ("TOKEN",)


def test_a_tool_needs_a_docstring():
    with pytest.raises(SchemaError, match="no docstring"):

        @tool
        def undocumented(x: str) -> str:
            return x


def test_unknown_effects_are_rejected():
    with pytest.raises(SchemaError, match="unknown effects"):

        @tool(effects="mostly-harmless")
        def sneaky(x: str) -> str:
            """Do something."""
            return x


def test_varargs_are_rejected():
    with pytest.raises(SchemaError, match=r"\*args"):

        @tool
        def loose(*args: str) -> str:
            """Take anything."""
            return ""


def test_unannotated_parameters_are_rejected():
    with pytest.raises(SchemaError, match="no type annotation"):

        @tool
        def untyped(x) -> str:
            """Take anything."""
            return str(x)


def test_side_effecting_is_read_versus_everything_else():
    @tool(effects="read")
    def r() -> str:
        """Read."""
        return ""

    @tool(effects=["read", "network"])
    def rn() -> str:
        """Read and fetch."""
        return ""

    assert not r.spec.side_effecting
    assert rn.spec.side_effecting


@pytest.mark.parametrize(
    "args,message",
    [
        ({}, "missing required"),
        ({"host": "a", "extra": 1}, "unexpected argument"),
        ({"host": 7}, "should be string"),
        ({"host": "a", "port": "443"}, "should be integer"),
        ({"host": "a", "scheme": "ftp"}, "must be one of"),
    ],
)
def test_validation_rejects_bad_calls(args, message):
    @tool
    def lookup(host: str, port: int = 443, scheme: Literal["http", "https"] = "https") -> str:
        """Look up a service."""
        return host

    with pytest.raises(SchemaError, match=message):
        validate_args(lookup.spec.input_schema, args)


def test_booleans_are_not_integers():
    @tool
    def counted(n: int) -> str:
        """Count."""
        return str(n)

    with pytest.raises(SchemaError):
        validate_args(counted.spec.input_schema, {"n": True})


def test_pep604_optional_is_supported_as_well_as_typing_optional():
    @tool
    def modern(name: str | None = None, count: int | None = None) -> str:
        """Both spellings have to work; people write the new one."""
        return name or ""

    properties = modern.spec.input_schema["properties"]
    assert properties["name"] == {"type": "string"}
    assert properties["count"] == {"type": "integer"}
    assert modern.spec.input_schema["required"] == []


def test_a_union_of_two_real_types_is_rejected():
    with pytest.raises(SchemaError, match="only Optional"):

        @tool
        def ambiguous(value: str | int) -> str:
            """Take either."""
            return str(value)
