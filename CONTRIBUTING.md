# Contributing

## Getting set up

```
git clone https://github.com/y0anfa/secure-agents
cd secure-agents
pip install -e '.[dev]'
pytest
pytest examples
```

## What this project is trying to be

Small enough to read in an afternoon. That is the adoption argument for a
security library, so API surface is a cost, not a feature, and a pull request
that adds a concept has to carry its weight against that.

Three rules that decide most reviews:

**The core stays dependency-free.** Every transitive dependency is something
an adopter has to diligence. A new runtime dependency in `secure_agents`
needs a very good argument; an optional extra is usually the answer.

**Changes get checked against the [threat model](docs/THREAT_MODEL.md).**
Section 9 is a five-question gate with worked rejections, so you can
self-serve the answer before opening a PR. An API that breaks one of the ten
invariants in section 6 is rejected rather than debated.

**A security claim ships with a test that would fail without it.** If a
change means the library stops something, there is a test asserting it stops,
and if it is user-facing, an example demonstrating it.

## Do not trim the test matrix

`pytest` runs on Linux and macOS, four Python versions each. That looks like
more than a small library needs, and the macOS half is the half to leave
alone.

The sandbox's limits are `setrlimit` calls, so what they actually do is a
property of the kernel rather than of this code. Darwin accepts `RLIMIT_AS`
and then ignores it, which meant `memory_mb` silently did nothing on macOS
while `Subprocess.describe()` reported a cap into the audit log. A
Linux-only matrix cannot catch that class of bug, structurally, no matter
how many tests it runs.

Two tests are platform-sensitive and worth knowing about before you move
them: `test_a_greedy_tool_hits_the_memory_limit` skips where the limit is
unenforced, and `test_fork_allows_tools_defined_in_main` uses
`start_method="fork"`, which is the classic macOS crash case when the parent
process is multi-threaded. It currently runs before the tests that start an
HTTP server thread. If you reorder that file, or add parallel test
execution, that is the one that breaks.

## Actions are pinned to commit SHAs

Every `uses:` in `.github/workflows/` names a full 40-character commit SHA
with the version in a trailing comment:

```yaml
- uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
```

A tag is mutable. Whoever controls an action's repository can move `v4` to
different code at any time, and it then runs in our CI with a token scoped to
this repository. A SHA is the only reference that cannot be moved under us.
This project's whole argument is about bounding what untrusted code can
reach, so the release process is not the place to make the opposite
assumption.

Dependabot proposes these updates weekly and rewrites the trailing comment
along with the SHA, so pinning does not mean going stale. Do not replace a
SHA with a tag to make an update easier to read.

If you ever resolve one by hand, ask for the commit and not the tag object:

```
git ls-remote --tags https://github.com/github/codeql-action 'refs/tags/v3^{}'
```

`github/codeql-action` uses annotated tags, so plain `refs/tags/v3` gives you
the tag object's SHA. Pinning to that fails at run time with an unresolvable
action, and the SHA looks entirely correct while it does. `actions/checkout`
and `actions/setup-python` use lightweight tags, where both forms agree,
which is what makes the difference easy to miss.

## Docs and examples

The examples are executable documentation. `pytest examples` runs them, and
the assertions are the security claims their READMEs make. If you change
behaviour an example depends on, update the example and its README in the
same PR.

`examples/quickstart.py` is the code in the root README. If you change one,
change the other, and paste the real output rather than a description of it.

## Before you open a PR

```
ruff check .
ruff format --check .
mypy
pytest
pytest examples
```

Commits explain why, not what; the diff covers what. No generated files by
hand: regenerate with the tooling.
