# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [semantic versioning](https://semver.org/), with one extra
promise: **the meaning of a policy does not widen in a minor or patch
release.** If a rule allowed something in 0.1, it will not silently allow
more in 0.2. Narrowing may happen in a minor release and will be called out
here.

## [Unreleased]

## [0.1.0]

First release. The API will change; the version number is meant literally.

### Added

- `Agent`, the loop, with policy between the model's request and the call
- `@tool`, deriving a strict JSON schema from the signature and docstring
- `Policy` with a deny default, argument predicates (`under`, `host_in`,
  `in_`, `equals`, `matches`, `max_len`), effect matching, and `from_dict`
- Provenance tracking, with automatic escalation of side-effecting calls to
  `ask` once the context is tainted
- `Subprocess` sandbox with resource limits, a minimal environment and an
  egress allowlist; `InProcess` for a first run
- `Secret` handles resolved inside the sandbox, and redaction of known secret
  values from tool results
- `JsonlAudit` with a SHA-256 hash chain and `verify_chain`
- `ScriptedModel`, so the whole loop including policy is testable without a
  network call
- Three worked examples, each with tests asserting the attack is stopped
