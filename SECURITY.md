# Reporting a vulnerability

Please report security issues privately through GitHub's
[private vulnerability reporting](https://github.com/y0anfa/secure-agents/security/advisories/new)
rather than in a public issue.

Include what you tried, what happened, and which invariant from the
[threat model](docs/THREAT_MODEL.md) you believe it breaks. A working proof of
concept against a checked-out copy is ideal.

## What counts

A finding is in scope if it breaks one of the threat model's invariants. In
particular:

- a tool call that executes without a matching policy decision
- a model-produced value reaching a shell, a path, or a URL without its check
- a secret value appearing in the context window, a tool argument, or a log
- an audit record that is missing, or that follows the effect it describes
- a sandboxed tool reaching a host outside its egress allowlist, by any route
  that does not require native code
- a tool set that completes the lethal trifecta and still constructs

## What does not

- A model following injected instructions. That is assumed, not defended
  against; see the README. The finding is what the model could then *reach*.
- Escaping `Subprocess` using `ctypes`, a native extension, or anything else
  inside the process. `Subprocess` is documented as a blast-radius reducer,
  not a boundary. If you can escape a `Sandbox` implementation that claims to
  be a boundary, that is very much in scope.
- Anything requiring the deployer to have written a policy that allows it.

We will acknowledge within a few working days and aim to have a fix or a
public position within thirty.
