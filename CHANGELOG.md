# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [semantic versioning](https://semver.org/), with one extra
promise: **the meaning of a policy does not widen in a minor or patch
release.** If a rule allowed something in 0.1, it will not silently allow
more in 0.2. Narrowing may happen in a minor release and will be called out
here.

## [Unreleased]

### Added

- A `Publish` workflow that releases to PyPI with Trusted Publishing, so there
  is no long-lived API token in this repository. It runs only when a GitHub
  release is published, and refuses to build if the tag and the version in
  `pyproject.toml` disagree.
- A CycloneDX SBOM and a GitHub build provenance attestation, produced by that
  workflow and attached to the release. The SBOM is generated from a clean
  environment holding only the built wheel, so for the core it is empty, which
  is the dependency-free claim in a form that can be checked rather than read.
- `docs/releasing.md`, including the PyPI and GitHub environment setup, which
  has to be done once by the account that will own the project.
- `py.typed`. The package is fully typed and mypy already checks it, but
  without the marker every downstream user saw `Any`.

### Changed

- Packaging metadata now uses a PEP 639 license expression (`Apache-2.0`) and
  ships `LICENSE` in the wheel. The deprecated `License ::` classifier is gone,
  because PyPI rejects metadata that carries both.

### Notes

- CodeQL is configured but skipped while the repository is private, because
  code scanning on a private repository needs GitHub Advanced Security. The
  workflow is gated on repository visibility and starts running by itself
  when the repo is published.

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
