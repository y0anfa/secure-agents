# What this does not protect against

Read this before you depend on the library.

A security tool that is vague about its limits makes you less safe, because
you will assume it covers something it does not. Everything below is a
deliberate boundary, not a missing feature, unless it says otherwise.

## It does not detect prompt injection

There is no classifier and no filter. An injection that lands still directs
the model, and the model will still ask for the tool call the attacker wants.

What changes is what happens next: the call meets the policy, and the policy
knows the context is tainted. The attack is not prevented, its consequences
are bounded. If you need "the model was never fooled", nothing here provides
that, and be sceptical of anything that claims to.

## Policy checks arguments, not behaviour

`arg("path").under("/srv/data")` checks the string the model supplied. If
your `read_file` tool takes a path and then reads something else, policy has
no idea. The rules govern the request, not the implementation.

The sandbox is the backstop for that, and tools are your own code, so review
them the way you review anything else that runs with your credentials.

## The default sandbox is not a sandbox

`Agent(...)` with no `sandbox=` uses `InProcess`, which runs the tool in your
interpreter with your privileges, your environment and your network. It is
the default because it is what a first run needs, not because it is safe.
`Subprocess(egress=Egress.deny_all())` is the one to reach for.

## `Subprocess` is containment, not isolation

It gives a fresh interpreter with `RLIMIT_AS`, `RLIMIT_CPU` and `RLIMIT_FSIZE`
set, a minimal environment, and no inherited memory under `spawn`. That stops
a tool that loops, allocates, or fills a disk.

It is not a boundary against hostile code running in the child. There is no
namespace, seccomp filter or user separation. Code that wants out can get
out. If you are running code you did not write, put a real sandbox
underneath.

## The egress guard patches `socket`

`Egress.allow(...)` works by wrapping `socket.getaddrinfo` and
`socket.socket.connect` inside the child. It reliably stops the realistic
case, which is a tool or one of its dependencies reaching a host nobody
intended.

It does not stop code that deliberately evades it: raw syscalls, `ctypes`, a
subprocess of its own. For an enforceable boundary, use a network namespace
or an egress proxy outside the process, and treat this as the second layer.

## The audit log is tamper-evident, not tamper-proof

`JsonlAudit` hash-chains records, so a deleted or edited line is detectable
by `verify_chain`. Anyone who can rewrite the file can also recompute the
chain and make it verify again.

The property only holds if the log lands somewhere the agent's own
credentials cannot reach. Ship it off the machine.

## Redaction is best-effort

`Redactor` removes known secret values from tool results before they reach
the model. It knows the values the tool declared, and only those, and skips
anything shorter than six characters because short strings collide with
ordinary words.

A tool that returns a secret it derived, re-encoded, or read from somewhere
it did not declare will leak it.

## Policy governs tool calls, not what the model says

The final answer text is not filtered. If private data reached the context,
the model can put it in its reply. Policy stops it being sent somewhere by a
tool; it does not stop it being in the output that your application then
displays, logs, or forwards.

## Taint is per-run and coarse

Once any tool has returned anything, the whole context is tainted for the
rest of the run. There is no per-value tracking, so a call that only touches
trusted data still escalates.

This is conservative on purpose, and it has a real cost in ergonomics. The
escape hatch is `when_tainted=Decision.ALLOW` on a specific rule, which is
deliberately something a reviewer can grep for.

## Denials are reported to the model by default

The default `on_deny="report"` hands the refusal back so the agent can try
something else. It also tells an attacker probing through the model which
calls are blocked. Set `on_deny="raise"` if that trade is wrong for you.

## The model provider sees everything

Prompts, tool schemas and every tool result go to whichever API you
configured. Nothing here is a confidentiality control against the provider.

## Not addressed at all

- Model supply chain, weights, or the provider's infrastructure
- Denial of service against your own agent
- Multi-tenant isolation between agents in one process
- Anything about the content of what the model generates

For the full reasoning, positions and invariants, see the
[threat model](THREAT_MODEL.md).
