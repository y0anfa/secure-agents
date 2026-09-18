import pytest
from demo_tools import echo, fetch_url, read_inbox, read_ticket, send_email, write_note

from secure_agents import (
    Agent,
    Decision,
    Policy,
    ScriptedModel,
    SecurityConfigError,
    arg,
    deny_all_approver,
    find_trifecta,
)

ALL_THREE = [read_inbox, fetch_url, send_email]


def agent(tools, policy, **kwargs):
    kwargs.setdefault("approver", deny_all_approver)
    return Agent(model=ScriptedModel([]), tools=tools, policy=policy, **kwargs)


def test_the_legs_are_read_off_the_declarations():
    legs = find_trifecta([t.spec for t in ALL_THREE])
    assert legs.private == ("read_inbox",)
    assert legs.untrusted == ("fetch_url",)
    assert "send_email" in legs.external
    assert legs.complete


def test_external_is_derived_from_send_and_network_not_guessed():
    assert send_email.spec.effect_class == "External"
    assert fetch_url.spec.effect_class == "External"
    assert read_ticket.spec.effect_class == "Read"
    assert write_note.spec.effect_class == "Write"
    assert echo.spec.effect_class == "Read"


def test_an_open_trifecta_fails_construction():
    with pytest.raises(SecurityConfigError) as excinfo:
        agent(ALL_THREE, Policy.default_deny().allow("*", when_tainted=Decision.ALLOW))

    message = str(excinfo.value)
    assert "read_inbox" in message and "fetch_url" in message and "send_email" in message
    # The error has to be actionable, not just correct.
    assert "Resolve by one of" in message
    assert "acknowledge_exfiltration_risk" in message


def test_the_default_taint_escalation_is_enough_to_break_the_chain():
    # No explicit when_tainted: the external leg escalates to ask, so it is
    # not a live exfiltration channel and construction succeeds.
    built = agent(ALL_THREE, Policy.default_deny().allow("*"))
    assert built.trifecta.complete


def test_an_explicit_deny_on_the_external_leg_also_breaks_it():
    policy = Policy.default_deny().allow("read_inbox").deny("fetch_url").deny("send_email")
    assert agent(ALL_THREE, policy)


def test_a_fetch_tool_is_itself_an_exfiltration_channel():
    """Gating send_email alone is not enough.

    ``fetch_url`` makes an outbound request with a model-chosen URL, so the
    private data can leave in the query string. The check counts every tool
    with the network or send effect as a channel, which is why leaving
    ``fetch_url`` ungated still fails even when the mail tool is locked down.
    """
    policy = (
        Policy.default_deny()
        .allow("read_inbox")
        .allow("fetch_url", when_tainted=Decision.ALLOW)
        .deny("send_email")
    )
    with pytest.raises(SecurityConfigError, match="tainted: fetch_url"):
        agent(ALL_THREE, policy)


def test_two_legs_are_not_a_problem():
    wide = Policy.default_deny().allow("*", when_tainted=Decision.ALLOW)
    assert agent([read_inbox, send_email], wide)
    assert agent(
        [fetch_url, send_email], Policy.default_deny().allow("*", when_tainted=Decision.ALLOW)
    )


def test_the_risk_can_be_accepted_on_the_record():
    built = agent(
        ALL_THREE,
        Policy.default_deny().allow("*", when_tainted=Decision.ALLOW),
        acknowledge_exfiltration_risk="air-gapped runner, ticket SEC-412",
    )
    assert built.acknowledged_risk == "air-gapped runner, ticket SEC-412"


def test_the_acknowledgement_is_recorded_in_the_audit_log():
    from secure_agents import MemoryAudit
    from secure_agents import audit as events

    log = MemoryAudit()
    built = Agent(
        model=ScriptedModel(["nothing to do"]),
        tools=ALL_THREE,
        policy=Policy.default_deny().allow("*", when_tainted=Decision.ALLOW),
        approver=deny_all_approver,
        audit=log,
        acknowledge_exfiltration_risk="air-gapped runner, ticket SEC-412",
    )
    built.run("hello")
    started = log.of_type(events.RUN_STARTED)[0].data
    assert started["acknowledged_exfiltration_risk"] == "air-gapped runner, ticket SEC-412"
    assert started["trifecta_legs"]["private"] == ["read_inbox"]


def test_the_static_check_over_approximates_what_a_rule_permits():
    """A rule with an argument predicate might match, so it counts as a live
    channel. Guessing permissive here would be the expensive mistake."""
    policy = (
        Policy.default_deny()
        .allow("read_inbox")
        .allow("fetch_url", when_tainted=Decision.ALLOW)
        .allow("send_email", when=arg("to").in_(["ops@corp"]), when_tainted=Decision.ALLOW)
    )
    with pytest.raises(SecurityConfigError):
        agent(ALL_THREE, policy)


def test_an_unconditional_rule_stops_the_scan():
    # send_email is denied unconditionally by the first matching rule, so the
    # later permissive wildcard is unreachable and must not count.
    policy = Policy.default_deny().deny("send_email").allow("*", when_tainted=Decision.ALLOW)
    assert not policy.can_allow_when_tainted(send_email.spec)
    assert policy.can_allow_when_tainted(read_inbox.spec)
