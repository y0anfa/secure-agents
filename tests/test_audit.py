import json

from secure_agents import JsonlAudit, MemoryAudit, NullAudit, verify_chain
from secure_agents.audit import Event


def test_null_audit_accepts_and_discards():
    NullAudit().record(Event("anything"))


def test_memory_audit_is_falsy_when_empty_but_still_records():
    audit = MemoryAudit()
    assert len(audit) == 0
    audit.record(Event("call.requested", {"tool": "echo"}))
    assert audit.of_type("call.requested")[0].data["tool"] == "echo"


def test_jsonl_audit_writes_one_object_per_line(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = JsonlAudit(path)
    audit.record(Event("call.requested", {"tool": "echo"}))
    audit.record(Event("call.completed", {"tool": "echo"}))

    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert [r["type"] for r in records] == ["call.requested", "call.completed"]
    assert records[0]["prev"] == "genesis"
    assert records[1]["prev"] == records[0]["hash"]


def test_an_intact_chain_verifies(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = JsonlAudit(path)
    for i in range(5):
        audit.record(Event("call.requested", {"n": i}))
    assert verify_chain(path) == (True, None)


def test_an_edited_record_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = JsonlAudit(path)
    for i in range(4):
        audit.record(Event("call.requested", {"n": i}))

    lines = path.read_text().splitlines()
    record = json.loads(lines[2])
    record["n"] = 99
    lines[2] = json.dumps(record, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")

    assert verify_chain(path) == (False, 3)


def test_a_deleted_record_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    audit = JsonlAudit(path)
    for i in range(4):
        audit.record(Event("call.requested", {"n": i}))

    lines = path.read_text().splitlines()
    del lines[1]
    path.write_text("\n".join(lines) + "\n")

    ok, line = verify_chain(path)
    assert not ok and line == 2


def test_a_reopened_log_continues_the_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    JsonlAudit(path).record(Event("a"))
    JsonlAudit(path).record(Event("b"))
    assert verify_chain(path) == (True, None)
