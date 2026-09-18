"""The record of what the agent did and why.

An agent that cannot be reviewed after the fact cannot be trusted with
anything interesting. Every policy decision, approval, tool call and result
lands here, including the ones that were denied.

:class:`JsonlAudit` hash-chains its entries: each record carries the SHA-256 of
the previous one, so a deleted or edited line is detectable with
:func:`verify_chain`. That is tamper *evidence*, not tamper proofing; anyone
who can rewrite the file can recompute the chain. Ship the file somewhere the
agent's own credentials cannot reach if that matters to you.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

RUN_STARTED = "run.started"
RUN_FINISHED = "run.finished"
MODEL_TURN = "model.turn"
CALL_REQUESTED = "call.requested"
CALL_INVALID = "call.invalid"
POLICY_DECISION = "policy.decision"
APPROVAL_REQUESTED = "approval.requested"
APPROVAL_RESOLVED = "approval.resolved"
CALL_COMPLETED = "call.completed"
CALL_FAILED = "call.failed"
CALL_DENIED = "call.denied"
BUDGET_EXCEEDED = "budget.exceeded"


@dataclass(frozen=True)
class Event:
    type: str
    data: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {"ts": round(self.ts, 6), "type": self.type, **self.data}


class AuditLog(Protocol):
    def record(self, event: Event) -> None: ...


class NullAudit:
    """Discards everything. The default, so the SDK writes no files unless
    asked, but not what you want in production."""

    def record(self, event: Event) -> None:
        return None


class MemoryAudit:
    """Keeps events in a list. Useful in tests and for inspecting a run."""

    def __init__(self) -> None:
        self.events: list[Event] = []

    def record(self, event: Event) -> None:
        self.events.append(event)

    def of_type(self, event_type: str) -> list[Event]:
        return [e for e in self.events if e.type == event_type]

    def __iter__(self) -> Iterator[Event]:
        return iter(self.events)

    def __len__(self) -> int:
        return len(self.events)


class JsonlAudit:
    """Append-only JSONL with a SHA-256 hash chain.

    Each line is ``{"ts", "type", ..., "prev", "hash"}`` where ``hash`` covers
    the record and ``prev``. Opened with ``O_APPEND`` and flushed per record,
    so two processes appending to the same file interleave lines without
    losing any, though their chains will interleave too: give each run its own
    file if you intend to verify.
    """

    def __init__(self, path: str | os.PathLike[str], fsync: bool = False) -> None:
        self.path = Path(path)
        self.fsync = fsync
        self._lock = threading.Lock()
        self._prev = self._last_hash()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return "genesis"
        last = "genesis"
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    try:
                        last = json.loads(line).get("hash", last)
                    except json.JSONDecodeError:
                        continue
        return last

    def record(self, event: Event) -> None:
        with self._lock:
            payload = event.to_dict()
            payload["prev"] = self._prev
            payload["hash"] = _digest(payload)
            line = json.dumps(payload, sort_keys=True, default=_fallback)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
                handle.flush()
                if self.fsync:
                    os.fsync(handle.fileno())
            self._prev = payload["hash"]


def _digest(payload: dict[str, Any]) -> str:
    body = {k: v for k, v in payload.items() if k != "hash"}
    return hashlib.sha256(
        json.dumps(body, sort_keys=True, default=_fallback).encode("utf-8")
    ).hexdigest()


def _fallback(value: Any) -> str:
    return repr(value)


def verify_chain(path: str | os.PathLike[str]) -> tuple[bool, int | None]:
    """Check a JSONL audit file's hash chain.

    Returns ``(True, None)`` if intact, or ``(False, line_number)`` pointing at
    the first record that does not follow from its predecessor.
    """
    prev = "genesis"
    with Path(path).open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                return False, number
            if record.get("prev") != prev or record.get("hash") != _digest(record):
                return False, number
            prev = record["hash"]
    return True, None
