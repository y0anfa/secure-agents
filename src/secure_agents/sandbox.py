"""Where tool side effects actually happen.

Read this before you rely on it.

:class:`Subprocess` gives you a fresh interpreter per call, CPU/memory/file-size
limits, a wall-clock kill, an egress allowlist, and a JSON-only channel home,
so the parent never unpickles anything the tool produced. That is a blast
radius reducer. It is **not** a boundary against hostile native code: a tool
that calls ``ctypes`` can undo the egress guard, and ``RLIMIT_AS`` will not
stop it reading a file the process can already open.

If a tool's input can be attacker-controlled and its code is not yours, put a
real boundary underneath: a container with a seccomp profile, gVisor, a
microVM. :class:`Sandbox` is a three-line protocol precisely so that swapping
in your own is easy; the rest of the SDK does not care which one it is talking
to.

:class:`InProcess` has no isolation at all and says so in its name. It is the
right choice for tools you wrote, that touch nothing dangerous, where the
policy layer is doing the work.
"""

from __future__ import annotations

import json
import multiprocessing
import os
from dataclasses import dataclass
from typing import Any, Protocol

from .errors import SandboxError, ToolError
from .tools import Tool

DEFAULT_MEMORY_MB = 512
DEFAULT_CPU_SECONDS = 10
DEFAULT_MAX_WRITE_MB = 64
_RESULT_LIMIT = 256 * 1024
"""Tool results larger than this are truncated. A 40MB file read is not a
useful tool result, it is a context-window denial of service."""


# --------------------------------------------------------------------------
# Egress
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Egress:
    """Which hosts a sandboxed tool may talk to."""

    allowed_hosts: frozenset[str] = frozenset()
    allow_all: bool = False

    @classmethod
    def deny_all(cls) -> Egress:
        return cls()

    @classmethod
    def allow(cls, *hosts: str) -> Egress:
        """Allow these hosts. A leading dot allows subdomains:
        ``Egress.allow(".internal.example.com")``."""
        return cls(frozenset(h.lower() for h in hosts))

    @classmethod
    def unrestricted(cls) -> Egress:
        return cls(allow_all=True)

    def permits(self, host: str | None) -> bool:
        if self.allow_all:
            return True
        if not host:
            return False
        host = host.lower()
        return any(
            host == allowed or (allowed.startswith(".") and host.endswith(allowed))
            for allowed in self.allowed_hosts
        )

    def describe(self) -> str:
        if self.allow_all:
            return "unrestricted"
        if not self.allowed_hosts:
            return "no network"
        return ", ".join(sorted(self.allowed_hosts))


class EgressDenied(SandboxError):
    """A sandboxed tool tried to reach a host the egress policy does not allow."""


# --------------------------------------------------------------------------
# Sandboxes
# --------------------------------------------------------------------------


class Sandbox(Protocol):
    """Runs one tool call and returns its result.

    Implement this to plug in a container, a microVM, or a remote worker. The
    agent expects a JSON-serializable return value, and expects failures as
    :class:`~secure_agents.errors.ToolError` (the tool's fault, reported to the
    model) or :class:`~secure_agents.errors.SandboxError` (the boundary's
    fault, also reported, but worth alerting on).
    """

    def execute(self, tool: Tool, args: dict[str, Any], secrets: dict[str, str]) -> Any: ...

    def describe(self) -> str: ...


class InProcess:
    """No isolation. The tool runs in this interpreter, with this process's
    file descriptors, environment and network.

    Named explicitly so that ``sandbox=InProcess()`` reads as a decision in a
    code review rather than as a default nobody chose.
    """

    def execute(self, tool: Tool, args: dict[str, Any], secrets: dict[str, str]) -> Any:
        kwargs = dict(args)
        if tool.spec.secrets:
            kwargs["secrets"] = secrets
        try:
            return _cap(tool.fn(**kwargs))
        except Exception as exc:
            raise ToolError(f"{tool.name} raised {type(exc).__name__}: {exc}") from exc

    def describe(self) -> str:
        return "in-process (no isolation)"


class Subprocess:
    """Runs each call in a fresh child interpreter with resource limits.

    Args:
        timeout_s: Wall-clock limit. The tool's own ``timeout_s`` wins if it is
            lower.
        memory_mb: Address-space limit (``RLIMIT_AS``).
        cpu_s: CPU-time limit (``RLIMIT_CPU``).
        max_write_mb: Largest file the tool may write (``RLIMIT_FSIZE``).
        egress: Which hosts the tool may reach.
        env: The child's entire environment. Defaults to a minimal one, so a
            tool cannot read credentials that happen to be exported in the
            parent. Secrets a tool declares are passed separately.
        start_method: ``"spawn"`` (default) gives the child no inherited
            memory. It requires tools to live in an importable module, not in
            ``__main__``. ``"fork"`` lifts that requirement and the isolation
            with it.

    Note:
        Because ``spawn`` re-imports the module that started the process, a
        script that builds and runs an agent has to do it under
        ``if __name__ == "__main__":``. This is Python's standard
        multiprocessing idiom, not something this SDK adds, but it is the
        first thing people hit.
    """

    def __init__(
        self,
        *,
        timeout_s: float = 30.0,
        memory_mb: int = DEFAULT_MEMORY_MB,
        cpu_s: int = DEFAULT_CPU_SECONDS,
        max_write_mb: int = DEFAULT_MAX_WRITE_MB,
        egress: Egress | None = None,
        env: dict[str, str] | None = None,
        start_method: str = "spawn",
    ) -> None:
        self.timeout_s = timeout_s
        self.memory_mb = memory_mb
        self.cpu_s = cpu_s
        self.max_write_mb = max_write_mb
        self.egress = egress if egress is not None else Egress.deny_all()
        self.env = env
        self.start_method = start_method

    def describe(self) -> str:
        return (
            f"subprocess({self.start_method}), {self.memory_mb}MB, {self.cpu_s}s cpu, "
            f"egress: {self.egress.describe()}"
        )

    def execute(self, tool: Tool, args: dict[str, Any], secrets: dict[str, str]) -> Any:
        if self.start_method == "spawn" and tool.module == "__main__":
            raise SandboxError(
                f"tool {tool.name!r} is defined in __main__, which the spawn sandbox "
                "cannot import without re-running your script. Move tools into a "
                "module, or pass start_method='fork'."
            )

        ctx = multiprocessing.get_context(self.start_method)
        parent_conn, child_conn = ctx.Pipe(duplex=False)
        limits = {
            "memory_mb": self.memory_mb,
            "cpu_s": self.cpu_s,
            "max_write_mb": self.max_write_mb,
        }
        process = ctx.Process(  # type: ignore[attr-defined]
            target=_child_main,
            args=(
                child_conn,
                tool.module,
                tool.qualname,
                json.dumps(args),
                secrets if tool.spec.secrets else {},
                limits,
                self.egress,
                self.env if self.env is not None else _minimal_env(),
            ),
            daemon=True,
        )
        deadline = min(self.timeout_s, tool.spec.timeout_s)
        process.start()
        child_conn.close()
        try:
            if not parent_conn.poll(deadline):
                raise SandboxError(f"{tool.name} exceeded its {deadline}s time limit")
            payload = parent_conn.recv()
        except EOFError as exc:
            raise SandboxError(
                f"{tool.name} died without returning a result "
                f"(exit code {process.exitcode}). Two usual causes: a resource "
                "limit (raise memory_mb or cpu_s), or a script that calls the "
                "agent at module level -- the spawn sandbox re-imports the "
                "calling module, so put your call under "
                'if __name__ == "__main__":'
            ) from exc
        finally:
            parent_conn.close()
            _reap(process)

        # The child speaks JSON only: nothing produced inside the sandbox is
        # ever unpickled out here.
        message = json.loads(payload)
        if message["status"] == "ok":
            return message["result"]
        if message["status"] == "egress":
            raise EgressDenied(message["error"])
        if message["status"] == "sandbox":
            raise SandboxError(message["error"])
        raise ToolError(message["error"])


def _reap(process: multiprocessing.process.BaseProcess) -> None:
    if process.is_alive():
        process.terminate()
        process.join(2)
    if process.is_alive():  # pragma: no cover - only if SIGTERM is ignored
        process.kill()
        process.join(1)
    process.close()


def _minimal_env() -> dict[str, str]:
    """A child environment with nothing inherited but what Python needs."""
    keep = ("PATH", "LANG", "LC_ALL", "TZ", "HOME", "TMPDIR", "SYSTEMROOT")
    return {k: os.environ[k] for k in keep if k in os.environ}


def _cap(result: Any) -> Any:
    if isinstance(result, str) and len(result) > _RESULT_LIMIT:
        return result[:_RESULT_LIMIT] + f"\n[truncated: {len(result)} bytes total]"
    return result


# --------------------------------------------------------------------------
# Child process
# --------------------------------------------------------------------------


def _child_main(
    conn: Any,
    module_name: str,
    qualname: str,
    args_json: str,
    secrets: dict[str, str],
    limits: dict[str, int],
    egress: Egress,
    env: dict[str, str],
) -> None:  # pragma: no cover - exercised across a process boundary
    """Entry point inside the sandbox. Everything here runs untrusted-adjacent."""
    try:
        os.environ.clear()
        os.environ.update(env)
        _apply_limits(limits)
        _install_egress_guard(egress)
        module = __import__(module_name, fromlist=["*"])
        target: Any = module
        for part in qualname.split("."):
            target = getattr(target, part)
        fn = getattr(target, "fn", target)

        kwargs = json.loads(args_json)
        if secrets:
            kwargs["secrets"] = secrets
        result = _cap(fn(**kwargs))
        try:
            payload = json.dumps({"status": "ok", "result": result})
        except (TypeError, ValueError):
            payload = json.dumps(
                {
                    "status": "error",
                    "error": (
                        f"{qualname} returned {type(result).__name__}, which is not "
                        "JSON-serializable; tool results must be text, numbers, "
                        "booleans, lists or dicts"
                    ),
                }
            )
        conn.send(payload)
    except EgressDenied as exc:
        conn.send(json.dumps({"status": "egress", "error": str(exc)}))
    except ImportError as exc:
        conn.send(
            json.dumps(
                {
                    "status": "sandbox",
                    "error": f"cannot import {module_name!r} in the sandbox: {exc}",
                }
            )
        )
    except MemoryError:
        conn.send(json.dumps({"status": "sandbox", "error": "tool exceeded its memory limit"}))
    except Exception as exc:
        conn.send(json.dumps({"status": "error", "error": f"{type(exc).__name__}: {exc}"}))
    finally:
        try:
            conn.close()
        except OSError:
            # The parent may already have hung up; there is nowhere to report
            # that to, and the process is about to exit anyway.
            pass


def _apply_limits(limits: dict[str, int]) -> None:  # pragma: no cover - child only
    try:
        import resource
    except ImportError:
        return  # Windows: the timeout and process boundary still apply.
    _set(resource.RLIMIT_CPU, limits["cpu_s"])
    _set(resource.RLIMIT_AS, limits["memory_mb"] * 1024 * 1024)
    _set(resource.RLIMIT_FSIZE, limits["max_write_mb"] * 1024 * 1024)
    _set(resource.RLIMIT_CORE, 0)


def _set(which: int, limit: int) -> None:  # pragma: no cover - child only
    import resource

    try:
        soft, hard = resource.getrlimit(which)
        ceiling = limit if hard == resource.RLIM_INFINITY else min(limit, hard)
        resource.setrlimit(which, (ceiling, hard))
    except (ValueError, OSError):
        pass


def _install_egress_guard(egress: Egress) -> None:  # pragma: no cover - child only
    """Block outbound connections to hosts the policy does not allow.

    Defense in depth, not a boundary: it patches the ``socket`` module, and a
    tool determined to get around it can. It stops the realistic case, which is
    a tool (or a library it calls) reaching somewhere nobody intended.
    """
    if egress.allow_all:
        return

    import socket

    resolved_ips: set[str] = set()
    real_getaddrinfo = socket.getaddrinfo
    real_connect = socket.socket.connect

    def guarded_getaddrinfo(host, port, *args, **kwargs):
        if not egress.permits(host):
            raise EgressDenied(f"egress to {host!r} is not allowed ({egress.describe()})")
        infos = real_getaddrinfo(host, port, *args, **kwargs)
        for info in infos:
            address = info[4]
            if address:
                resolved_ips.add(str(address[0]))
        return infos

    def guarded_connect(self, address):
        if isinstance(address, tuple) and address:
            host = str(address[0])
            if host not in resolved_ips and not egress.permits(host):
                raise EgressDenied(f"egress to {host!r} is not allowed ({egress.describe()})")
        return real_connect(self, address)

    socket.getaddrinfo = guarded_getaddrinfo
    socket.socket.connect = guarded_connect  # type: ignore[method-assign]
