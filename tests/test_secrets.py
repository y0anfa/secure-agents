import pytest

from secure_agents import Secret, SecretError
from secure_agents.secrets import Redactor


def test_a_secret_will_not_stringify_itself():
    secret = Secret("TOKEN", lambda name: "hunter2-and-then-some")
    with pytest.raises(SecretError):
        str(secret)
    with pytest.raises(SecretError):
        f"Bearer {secret}"


def test_repr_shows_the_name_not_the_value():
    secret = Secret("TOKEN", lambda name: "hunter2-and-then-some")
    assert repr(secret) == "Secret('TOKEN')"
    assert "hunter2" not in repr(secret)


def test_reveal_returns_the_value_and_missing_secrets_raise():
    assert Secret("TOKEN", lambda name: "value-long-enough").reveal() == "value-long-enough"
    with pytest.raises(SecretError, match="not set"):
        Secret("ABSENT", lambda name: None).reveal()


def test_redaction_replaces_values_in_tool_output():
    redactor = Redactor()
    redactor.register("TOKEN", "ghp_abcdefghijklmnop")
    assert redactor.redact("used ghp_abcdefghijklmnop ok") == "used [redacted:TOKEN] ok"


def test_short_values_are_not_redacted():
    # Redacting "abc" would shred any output containing that substring.
    redactor = Redactor()
    redactor.register("SHORT", "abc")
    assert redactor.redact("abcdef") == "abcdef"


def test_the_longest_matching_secret_wins():
    redactor = Redactor()
    redactor.register("OUTER", "prefix-secret-value")
    redactor.register("INNER", "secret-value")
    assert redactor.redact("prefix-secret-value") == "[redacted:OUTER]"
