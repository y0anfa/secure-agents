import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import demo_tools
import pytest
from demo_tools import echo, explode, fetch, hog, not_json, peek_env, slow, whoami

from secure_agents import InProcess, SandboxError, Subprocess, ToolError
from secure_agents.sandbox import Egress, EgressDenied
from secure_agents.tools import Tool


@pytest.fixture
def box():
    return Subprocess(timeout_s=10, memory_mb=256, cpu_s=5)


# -- in-process ------------------------------------------------------------


def test_in_process_runs_and_reports_failures():
    assert InProcess().execute(echo, {"text": "hi"}, {}) == "hi"
    with pytest.raises(ToolError, match="ValueError: boom"):
        InProcess().execute(explode, {}, {})


def test_in_process_names_itself_honestly():
    assert "no isolation" in InProcess().describe()


# -- subprocess ------------------------------------------------------------


def test_subprocess_runs_a_tool(box):
    assert box.execute(echo, {"text": "hello"}, {}) == "hello"


def test_a_tool_that_raises_becomes_a_tool_error(box):
    with pytest.raises(ToolError, match="ValueError: boom"):
        box.execute(explode, {}, {})


def test_a_slow_tool_is_killed(box):
    box.timeout_s = 1
    with pytest.raises(SandboxError, match="time limit"):
        box.execute(slow, {"seconds": 10}, {})


def test_a_greedy_tool_hits_the_memory_limit():
    box = Subprocess(timeout_s=20, memory_mb=128)
    with pytest.raises(SandboxError):
        box.execute(hog, {}, {})


def test_the_parent_environment_is_not_inherited(box):
    os.environ["SECURE_AGENTS_LEAK_CHECK"] = "should-not-be-visible"
    try:
        assert box.execute(peek_env, {"name": "SECURE_AGENTS_LEAK_CHECK"}, {}) == "<unset>"
    finally:
        del os.environ["SECURE_AGENTS_LEAK_CHECK"]


def test_an_explicit_environment_is_passed_through():
    box = Subprocess(env={"MY_SETTING": "on", "PATH": os.environ.get("PATH", "")})
    assert box.execute(peek_env, {"name": "MY_SETTING"}, {}) == "on"


def test_a_result_that_is_not_json_is_an_error_not_a_pickle(box):
    with pytest.raises(ToolError, match="not JSON-serializable"):
        box.execute(not_json, {}, {})


def test_secrets_reach_the_tool_without_passing_through_the_model(box):
    result = box.execute(whoami, {}, {"DEMO_TOKEN": "sekret-value-123"})
    assert result == "authenticated with sekret-value-123"


def test_spawn_refuses_tools_defined_in_main(box):
    orphan = Tool(spec=echo.spec, fn=echo.fn, module="__main__", qualname="echo")
    with pytest.raises(SandboxError, match="__main__"):
        box.execute(orphan, {"text": "hi"}, {})


def test_fork_allows_tools_defined_in_main():
    box = Subprocess(start_method="fork", timeout_s=10)
    orphan = Tool(spec=echo.spec, fn=demo_tools.echo.fn, module="demo_tools", qualname="echo")
    assert box.execute(orphan, {"text": "hi"}, {}) == "hi"


# -- egress ----------------------------------------------------------------


def test_egress_is_denied_by_default(box):
    with pytest.raises(EgressDenied, match="not allowed"):
        box.execute(fetch, {"url": "https://example.com/"}, {})


def test_egress_denies_hosts_outside_the_allowlist():
    box = Subprocess(timeout_s=10, egress=Egress.allow("api.example.com"))
    with pytest.raises(EgressDenied):
        box.execute(fetch, {"url": "https://evil.example.net/"}, {})


def test_egress_allows_listed_hosts():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        box = Subprocess(timeout_s=10, egress=Egress.allow("127.0.0.1"))
        assert box.execute(fetch, {"url": f"http://127.0.0.1:{port}/"}, {}) == "ok"
    finally:
        server.shutdown()


def test_egress_policy_describes_itself():
    assert Egress.deny_all().describe() == "no network"
    assert Egress.unrestricted().describe() == "unrestricted"
    assert Egress.allow("a.com", "b.com").describe() == "a.com, b.com"


def test_subdomain_wildcards():
    egress = Egress.allow(".example.com")
    assert egress.permits("api.example.com")
    assert not egress.permits("example.com.evil.net")
    assert not egress.permits(None)
