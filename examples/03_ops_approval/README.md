# Ops agent with an approval gate

An agent that can restart and terminate instances, with a human required for
the irreversible one, and a paper trail that outlives the run.

```
python ops.py
pytest test_ops_approval.py
```

## What to look for

The same run twice, once with nobody watching and once with an approver.

**Unattended**, `terminate_instance` is declined and the rest of the work
still happens. That is the right failure mode for a scheduled job: the agent
does the nine things that were fine and leaves the tenth for a person.

**Attended**, the approver sees the call, its arguments, and the policy's
reason before answering.

**`restart_instance` does not ask**, and the reason is worth reading in the
policy. Listing the fleet taints the context, so by default every subsequent
restart would need a human, which is how an agent becomes more annoying than
useful. The rule opts out with `when_tainted=Decision.ALLOW`. That override
is a deliberate line somebody reviewing the policy will see, rather than a
default nobody chose.

## The audit trail

```
  33 events in audit.jsonl
  chain intact: True
  after deleting the approval records, intact: False (bad line: 14)
```

`JsonlAudit` hash-chains its records, so removing the evidence that a human
approved a termination is detectable. This is tamper *evidence*, not tamper
proofing: anyone who can rewrite the file can recompute the chain. The
property only holds if the log lands somewhere the agent's own credentials
cannot reach.

The events are stable strings (`policy.decision`, `approval.resolved`,
`call.completed`), so the file drops into a SIEM without a parser written
specially for it. The question after an incident is never "what did the model
say", it is "what did it actually do, and who said yes".
