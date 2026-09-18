# Security policy

## Reporting a vulnerability

Report privately through
[GitHub Security Advisories](https://github.com/y0anfa/secure-agents/security/advisories/new).
Please do not open a public issue for a suspected vulnerability.

We aim to acknowledge within **3 working days** and to give an initial
assessment, with a fix or a timeline, within **10 working days**. If you have
not heard back in that window, escalate by opening a public issue that says
only that you are waiting on a security report, with no details.

Coordinated disclosure, 90 days by default, shorter if a fix ships sooner and
longer only by agreement.

## What counts as a vulnerability here

This library sits between a model and a set of tools. That makes the scope
question sharper than usual, so it is worth being explicit.

**In scope.** Anything where the SDK's own mechanism fails to do what it
says:

- A tool call that runs despite a policy that should have denied it
- An argument predicate that can be bypassed: a path escaping `under()`, a
  host escaping `host_in()`, a schema check that lets an undeclared argument
  through
- Untrusted content that fails to taint the context, so an escalation that
  should have happened did not
- A secret reaching the model's context despite being declared
- An audit chain that verifies after a record was changed or removed
- Escaping `Subprocess` by a route the resource limits and the minimal
  environment were meant to close
- Any crash reachable from tool arguments the model controls

**Not in scope.** The model behaving badly is the condition this library is
built for, not a defect in it:

- The model being persuaded to attempt a call that policy then denies. That
  is the system working.
- A successful prompt injection as such. We do not detect injection and do
  not claim to.
- A policy that is too permissive because of how it was written. If the rule
  said `allow("read_file")`, that is what it granted.
- A tool implementation that ignores its own arguments, or leaks a secret it
  derived. Tools are your code.
- Evading the egress guard with `ctypes`, raw syscalls or a child process.
  It patches `socket` and is documented as defence in depth, not a boundary.
- Escaping `InProcess`, which is documented as no isolation at all.
- Anything in [docs/limits.md](docs/limits.md) under "Not addressed at all".

If you are unsure which side of that line something falls on, report it. A
report that turns out to be in the second list is still useful, because it
usually means the documentation was not clear enough.

## Supported versions

Pre-1.0: only the latest release. Fixes go into a new patch release, with an
advisory naming the affected versions.
