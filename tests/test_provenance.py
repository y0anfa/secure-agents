from secure_agents import Provenance, Source, Trust


def test_user_content_is_not_taint():
    assert not Provenance.from_user().tainted


def test_tool_output_taints_the_context():
    prov = Provenance.from_user().with_source(Source(Trust.UNTRUSTED, "tool:fetch"))
    assert prov.tainted
    assert prov.untrusted_labels == ("tool:fetch",)
    assert "tool:fetch" in prov.describe()


def test_sources_are_deduplicated_and_ordered():
    source = Source(Trust.UNTRUSTED, "tool:fetch")
    prov = Provenance.from_user().with_source(source).with_source(source)
    assert len(prov.sources) == 2


def test_trusted_sources_do_not_taint():
    prov = Provenance.from_user().with_source(Source(Trust.TRUSTED, "system"))
    assert not prov.tainted
    assert prov.describe() == "untainted"
