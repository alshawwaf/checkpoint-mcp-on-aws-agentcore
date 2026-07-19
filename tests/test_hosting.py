"""Offline tests for the AgentCore-hosted agent: the HTTP contract the runtime
container serves, and the pure provisioner helpers (no AWS)."""

import http.client
import json
import threading
from http.server import ThreadingHTTPServer

import pytest

from chkpmcpaws import _hosting_server as hs
from chkpmcpaws import hosting
from chkpmcpaws.config import StackConfig


# --- payload parsing ---------------------------------------------------------
def test_extract_task_shapes():
    assert hs.extract_task("  hello  ") == "hello"
    assert hs.extract_task({"prompt": "p"}) == "p"
    assert hs.extract_task({"task": "t"}) == "t"
    assert hs.extract_task({"input": "i"}) == "i"
    assert hs.extract_task({"query": "q"}) == "q"
    # precedence: first non-empty of TASK_KEYS
    assert hs.extract_task({"prompt": "first", "task": "second"}) == "first"
    # nothing usable
    assert hs.extract_task({"unrelated": "x"}) == ""
    assert hs.extract_task({"prompt": "   "}) == ""
    assert hs.extract_task(123) == ""


def test_run_invocation_no_task():
    out = hs.run_invocation({"nope": 1})
    assert "error" in out and "no task" in out["error"]


def test_run_invocation_delegates_to_agent(monkeypatch):
    captured = {}

    def fake_run_task_captured(cfg, session, task, model=None, session_id=None, actor=None):
        captured.update(task=task, session_id=session_id, actor=actor)
        return {"result": "ANSWER", "usage": {"in": 1}, "error": False}

    import chkpmcpaws.agent as agent
    monkeypatch.setattr(agent, "run_task_captured", fake_run_task_captured)
    out = hs.run_invocation({"prompt": "how many hosts?", "sessionId": "s1", "actor": "a1"})
    assert out["result"] == "ANSWER"
    assert captured == {"task": "how many hosts?", "session_id": "s1", "actor": "a1"}


# --- HTTP contract: GET /ping, POST /invocations (real socket, no AWS) -------
@pytest.fixture()
def server(monkeypatch):
    # stub the invocation so the server never touches AWS
    monkeypatch.setattr(hs, "run_invocation", lambda payload: {"result": "ok", "echo": payload})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), hs.Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address
    srv.shutdown()


def _request(addr, method, path, body=None):
    conn = http.client.HTTPConnection(*addr, timeout=5)
    headers = {"Content-Type": "application/json"} if body is not None else {}
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read().decode()
    conn.close()
    return resp.status, data


def test_ping_is_healthy(server):
    status, data = _request(server, "GET", "/ping")
    assert status == 200
    assert json.loads(data)["status"] == "Healthy"


def test_invocations_runs_agent(server):
    status, data = _request(server, "POST", "/invocations",
                            body=json.dumps({"prompt": "hi"}))
    assert status == 200
    out = json.loads(data)
    assert out["result"] == "ok" and out["echo"]["prompt"] == "hi"


def test_invocations_bad_json_is_400(server):
    status, data = _request(server, "POST", "/invocations", body="{not json")
    assert status == 400
    assert "invalid JSON" in json.loads(data)["error"]


def test_unknown_route_is_404(server):
    assert _request(server, "GET", "/nope")[0] == 404
    assert _request(server, "POST", "/wrong", body="{}")[0] == 404


def test_invocations_handler_never_leaks_exceptions(server, monkeypatch):
    monkeypatch.setattr(hs, "run_invocation", lambda p: (_ for _ in ()).throw(RuntimeError("boom")))
    status, data = _request(server, "POST", "/invocations", body=json.dumps({"prompt": "x"}))
    assert status == 500
    assert "RuntimeError" in json.loads(data)["error"]


# --- provisioner pure helpers ------------------------------------------------
def test_runtime_session_id_length_and_charset():
    import re
    for sid in (None, "s", "my-session_1", "weird/id with spaces", "x" * 200):
        rsid = hosting._runtime_session_id(sid)
        assert 33 <= len(rsid) <= 100, (sid, len(rsid))
        assert re.fullmatch(r"[A-Za-z0-9_-]+", rsid)


def test_runtime_session_id_prefix_is_wire_stable():
    # 'chkpmcp-session-' is a WIRE-LEVEL identifier: a resumed --session must
    # present the same runtimeSessionId across tool renames/upgrades, or it
    # loses warm-runtime affinity and splits session-grouped observability.
    # It deliberately does NOT track the package name (chkpmcpaws).
    assert hosting._runtime_session_id("soc-review").startswith(
        "chkpmcp-session-soc-review")


def test_bridge_session_id_prefix_is_wire_stable():
    # Same contract for the bridge Lambda: its source must keep emitting the
    # runtimeSessionId prefix the already-deployed Lambda uses.
    from chkpmcpaws import bridge
    assert '"chkpmcp-bridge-"' in bridge.HANDLER_PY
    assert "chkpmcpaws-bridge-" not in bridge.HANDLER_PY


def test_buildspec_has_login_build_push():
    spec = hosting._buildspec("us-east-1", "123456789012", "img:v1")
    assert "get-login-password" in spec
    assert "docker build -t img:v1" in spec
    assert "docker push img:v1" in spec


def test_exec_role_docs_shape():
    cfg = StackConfig()
    trust, perms = hosting._exec_role_docs(cfg, "123456789012", "us-east-1")
    assert trust["Statement"][0]["Principal"]["Service"] == "bedrock-agentcore.amazonaws.com"
    actions = {a for s in perms["Statement"] for a in
               ([s["Action"]] if isinstance(s["Action"], str) else s["Action"])}
    assert "bedrock:InvokeModel" in actions
    assert "bedrock:InvokeModelWithResponseStream" in actions
    assert "cognito-idp:DescribeUserPoolClient" in actions
