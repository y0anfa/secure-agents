# Releasing

A release of secure-agents is one human action: tag a commit, write the notes,
press publish. `.github/workflows/publish.yml` does the rest, and it will not
run any other way. There is no publish-on-merge, and there is no PyPI API token
in this repository.

## Why there is no token

The workflow publishes with [Trusted Publishing][tp]. PyPI is told, once, that
releases of `secure-agents` may come from the `publish.yml` workflow in
`y0anfa/secure-agents` and from nowhere else. At publish time GitHub mints a
short-lived OIDC token for that exact workflow run and PyPI exchanges it for an
upload credential that expires in minutes.

The practical difference from an API token is not convenience. A token is a
long-lived secret sitting in repository settings that any workflow with
`secrets` access can read, that survives the person who created it, and that
nobody notices is gone. There is nothing here to steal, scope wrong, or forget
to rotate.

[tp]: https://docs.pypi.org/trusted-publishers/

## One-time setup

This part cannot be done from CI, because it is the step that decides what CI
is allowed to do. It needs the PyPI account that will own the project.

**1. PyPI.** While the project does not exist yet, create it as a *pending*
publisher at <https://pypi.org/manage/account/publishing/>:

| Field | Value |
| --- | --- |
| PyPI Project Name | `secure-agents` |
| Owner | `y0anfa` |
| Repository name | `secure-agents` |
| Workflow name | `publish.yml` |
| Environment name | `pypi` |

**2. TestPyPI.** The same form at
<https://test.pypi.org/manage/account/publishing/>, with the environment name
`testpypi`. This exists so the first real release is not the first time the
setup is exercised.

**3. GitHub environments.** Create `pypi` and `testpypi` under Settings →
Environments. The names have to match what was registered above, because the
environment is part of what PyPI checks.

Protect the `pypi` environment: restrict it to the `main` branch and to tags,
and add yourself as a required reviewer if you want a second look between the
tag and the upload. The environment is the only place that rule can live; the
workflow cannot enforce it on itself.

## Rehearsal

Run the `Publish` workflow manually from the Actions tab with the default
`testpypi` target. It builds, checks, and uploads to TestPyPI. A Trusted
Publishing setup that is wrong fails at the upload step, and finding that out
on the real index means burning a version number, because PyPI does not allow
a version to be reused even after it is deleted.

## Cutting a release

1. Update `CHANGELOG.md`: move the entries under `Unreleased` into a version
   heading with today's date.
2. Bump `version` in `pyproject.toml`.
3. Merge that, and check CI is green on `main`.
4. Create a GitHub release with the tag `vX.Y.Z` on that commit.

The workflow refuses to build if the tag and `pyproject.toml` disagree, because
the tag is what people will read and the metadata is what they will install,
and those being different is the kind of thing nobody notices for a year.

## What ships alongside the package

- **A CycloneDX SBOM**, attached to the GitHub release as
  `secure-agents.cdx.json`. It is generated from a clean environment with only
  the built wheel installed in it, so it lists what an install actually pulls
  in rather than restating `pyproject.toml`. For the core that list is empty,
  which is the dependency-free claim in a form a procurement reviewer can read
  without taking anyone's word for it.
- **A build provenance attestation**, signed by GitHub, binding the exact
  distribution files to the workflow, repository and commit that produced them.

Someone who wants to check, rather than trust:

```
gh attestation verify secure_agents-0.1.0-py3-none-any.whl --repo y0anfa/secure-agents
```

## What this does not give you

The attestation says these files came out of this repository at this commit. It
says nothing about whether the code in that commit is any good, and it is not a
defence against a maintainer account being taken over: an attacker with push
access to `main` gets a valid attestation for whatever they pushed, because at
that point it genuinely did come from here.

What it does defend is the space between the commit and the file on PyPI, which
is where a stolen token would otherwise have let someone insert a build nobody
in this repository ever saw. Protecting the `pypi` environment with a required
reviewer is the control for the other half.
