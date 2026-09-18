import pytest
from demo_tools import echo, fetch, send_email

from secure_agents import Decision, Policy, Provenance, Source, ToolCall, Trust, arg
from secure_agents.policy import all_of, not_

CLEAN = Provenance.from_user()
TAINTED = CLEAN.with_source(Source(Trust.UNTRUSTED, "tool:fetch"))


def call(name, args=None, provenance=CLEAN):
    return ToolCall(id="c1", name=name, args=args or {}, provenance=provenance)


def test_the_default_is_deny():
    policy = Policy.default_deny()
    assert policy.decide(call("echo"), echo.spec).decision is Decision.DENY


def test_first_matching_rule_wins():
    policy = Policy.default_deny().deny("echo", reason="blocked").allow("echo")
    verdict = policy.decide(call("echo"), echo.spec)
    assert verdict.decision is Decision.DENY
    assert verdict.reason == "blocked"


def test_globs_match_tool_names():
    policy = Policy.default_deny().allow("send_*")
    assert policy.decide(call("send_email"), send_email.spec).decision is Decision.ALLOW
    assert policy.decide(call("echo"), echo.spec).decision is Decision.DENY


def test_rules_can_match_on_effects():
    policy = Policy.default_deny().deny("*", effects=["network"]).allow("*")
    assert policy.decide(call("fetch", {"url": "https://x"}), fetch.spec).decision is Decision.DENY
    assert policy.decide(call("echo", {"text": "hi"}), echo.spec).decision is Decision.ALLOW


def test_path_predicate_confines_an_argument(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    policy = Policy.default_deny().allow("echo", when=arg("text").under(str(root)))
    assert policy.decide(call("echo", {"text": str(root / "a.txt")}), echo.spec).allowed
    assert not policy.decide(call("echo", {"text": "/etc/shadow"}), echo.spec).allowed


def test_path_predicate_resolves_symlinks(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    (root / "escape").symlink_to("/etc")
    policy = Policy.default_deny().allow("echo", when=arg("text").under(str(root)))
    # The string is under the root; the file it points at is not.
    target = str(root / "escape" / "passwd")
    assert not policy.decide(call("echo", {"text": target}), echo.spec).allowed


def test_path_predicate_rejects_traversal(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    policy = Policy.default_deny().allow("echo", when=arg("text").under(str(root)))
    assert not policy.decide(call("echo", {"text": f"{root}/../secrets"}), echo.spec).allowed


def test_path_predicate_does_not_match_a_sibling_prefix(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    (tmp_path / "data-private").mkdir()
    policy = Policy.default_deny().allow("echo", when=arg("text").under(str(root)))
    assert not policy.decide(
        call("echo", {"text": str(tmp_path / "data-private" / "x")}), echo.spec
    ).allowed


def test_host_predicate_allows_subdomains_only_with_a_leading_dot():
    strict = Policy.default_deny().allow("fetch", when=arg("url").host_in(["example.com"]))
    wild = Policy.default_deny().allow("fetch", when=arg("url").host_in([".example.com"]))
    assert strict.decide(call("fetch", {"url": "https://example.com/a"}), fetch.spec).allowed
    sub = call("fetch", {"url": "https://api.example.com/a"})
    assert not strict.decide(sub, fetch.spec).allowed
    assert wild.decide(call("fetch", {"url": "https://api.example.com/a"}), fetch.spec).allowed
    assert not wild.decide(call("fetch", {"url": "https://notexample.com/a"}), fetch.spec).allowed


def test_combinators():
    policy = Policy.default_deny().allow(
        "fetch",
        when=all_of(arg("url").host_in([".example.com"]), not_(arg("url").matches(r".*admin.*"))),
    )
    assert policy.decide(call("fetch", {"url": "https://a.example.com/x"}), fetch.spec).allowed
    assert not policy.decide(
        call("fetch", {"url": "https://a.example.com/admin"}), fetch.spec
    ).allowed


# -- the interesting part: taint ------------------------------------------


def test_side_effecting_tools_escalate_to_ask_once_the_context_is_tainted():
    policy = Policy.default_deny().allow("send_email")
    clean = call("send_email", provenance=CLEAN)
    assert policy.decide(clean, send_email.spec).decision is Decision.ALLOW

    verdict = policy.decide(call("send_email", provenance=TAINTED), send_email.spec)
    assert verdict.decision is Decision.ASK
    assert verdict.escalated
    assert "tool:fetch" in verdict.reason


def test_read_only_tools_do_not_escalate():
    policy = Policy.default_deny().allow("echo")
    verdict = policy.decide(call("echo", provenance=TAINTED), echo.spec)
    assert verdict.decision is Decision.ALLOW
    assert not verdict.escalated


def test_escalation_can_be_overridden_per_rule():
    # An operator who has decided this particular send is safe on tainted
    # input has to say so explicitly, in one place, on the record.
    policy = Policy.default_deny().allow("send_email", when_tainted=Decision.ALLOW)
    assert policy.decide(call("send_email", provenance=TAINTED), send_email.spec).allowed

    strict = Policy.default_deny().allow("echo", when_tainted=Decision.DENY)
    assert strict.decide(call("echo", provenance=TAINTED), echo.spec).decision is Decision.DENY


def test_may_ask_is_exact_when_given_the_tool_specs():
    read_only = Policy.default_deny().allow("echo")
    assert not read_only.may_ask([echo.spec])
    assert read_only.may_ask([echo.spec, send_email.spec]) is False

    mixed = Policy.default_deny().allow("echo").allow("send_email")
    assert mixed.may_ask([echo.spec, send_email.spec])


# -- config form -----------------------------------------------------------


def test_policy_round_trips_through_plain_data(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    policy = Policy.from_dict(
        {
            "default": "deny",
            "rules": [
                {
                    "name": "reports",
                    "tools": "echo",
                    "decision": "allow",
                    "when": {"arg": "text", "under": str(root)},
                },
                {"tools": "*", "decision": "ask", "effects": ["send"]},
            ],
        }
    )
    assert policy.decide(call("echo", {"text": str(root / "a")}), echo.spec).allowed
    assert not policy.decide(call("echo", {"text": "/etc/passwd"}), echo.spec).allowed
    assert policy.decide(call("send_email"), send_email.spec).decision is Decision.ASK


def test_a_when_clause_with_no_known_test_is_an_error():
    with pytest.raises(ValueError, match="no known test"):
        Policy.from_dict(
            {"rules": [{"tools": "*", "decision": "allow", "when": {"arg": "path", "nope": 1}}]}
        )


def test_describe_lists_the_rules():
    policy = Policy.default_deny().allow("echo").ask("send_email")
    text = policy.describe()
    assert "ALLOW echo" in text and "ASK send_email" in text and "DEFAULT DENY" in text
