"""Tools for the repo assistant example, scoped to one directory."""

import subprocess
from pathlib import Path

from secure_agents import tool

WORKSPACE = (Path(__file__).parent / "workspace").resolve()


@tool(effects="read", exposure="private")
def read_file(path: str) -> str:
    """Read a file from the working copy.

    Args:
        path: Path to the file.
    """
    return Path(path).read_text(encoding="utf-8")


@tool(effects="write")
def write_file(path: str, content: str) -> str:
    """Write a file in the working copy.

    Args:
        path: Path to the file.
        content: The full new contents.
    """
    target = Path(path)
    target.write_text(content, encoding="utf-8")
    return f"wrote {len(content)} bytes to {target.name}"


@tool(effects="exec", timeout_s=10.0)
def run_command(command: str) -> str:
    """Run a build or test command in the working copy.

    Args:
        command: The command to run, for example "pytest -q".
    """
    completed = subprocess.run(  # noqa: S602
        command,
        shell=True,
        cwd=WORKSPACE,
        capture_output=True,
        text=True,
        timeout=10,
    )
    return (completed.stdout + completed.stderr).strip() or "(no output)"


OUTSIDE = (Path(__file__).parent / "outside_the_checkout").resolve()
PLANTED_SYMLINK = WORKSPACE / "notes.txt"


def ensure_fixtures() -> bool:
    """Plant a symlink inside the checkout that points out of it.

    Created at runtime rather than committed, so the example behaves the same
    on a checkout that did not preserve symlinks. This is the attack the
    ``under()`` predicate exists for: the path string starts with the
    workspace prefix, and a naive check would pass it.
    """
    if PLANTED_SYMLINK.is_symlink():
        return True
    try:
        PLANTED_SYMLINK.unlink(missing_ok=True)
        PLANTED_SYMLINK.symlink_to(OUTSIDE / "secret.txt")
    except OSError:
        # Some filesystems have no symlinks. The rest of the example still
        # demonstrates ordinary traversal and the command allowlist.
        return False
    return True
