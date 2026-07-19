"""HTTP entrypoint for the AgentCore-hosted agent (see chkpmcpaws.hosting).

The container this runs in implements the AgentCore Runtime HTTP contract:
    GET  /ping         -> 200  {"status": "Healthy"}   (health probe)
    POST /invocations  -> run the agent on the request payload, return the answer
listening on 0.0.0.0:8080.

This is the containerized twin of `agent --runtime local`: /invocations reuses
the exact same reason -> gateway -> guardrail -> tools loop (chkpmcpaws.agent),
just wrapped in the runtime's request/response envelope. The heavy lifting
(gateway discovery, Cognito token, Converse loop) stays in chkpmcpaws.agent so the
two runtimes can never drift.

LIVE-VALIDATED (2026-07-16): this contract (/ping + /invocations on :8080) was
exercised on a real AgentCore Runtime end to end -- see chkpmcpaws.hosting.
"""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8080"))
TASK_KEYS = ("prompt", "task", "input", "inputText", "query")


def extract_task(payload):
    """Pull the user's task text out of the invocation payload. Tolerates a few
    shapes so the caller convention can vary: a bare string, or a dict with any
    of TASK_KEYS."""
    if isinstance(payload, str):
        return payload.strip()
    if isinstance(payload, dict):
        for key in TASK_KEYS:
            v = payload.get(key)
            if isinstance(v, str) and v.strip():
                return v.strip()
    return ""


def run_invocation(payload):
    """Decoded payload -> JSON-serializable response dict. Orchestration only;
    all AWS work happens inside chkpmcpaws.agent.run_task_captured."""
    task = extract_task(payload)
    if not task:
        return {"error": "no task in payload (expected one of "
                + "/".join(TASK_KEYS) + " or a bare string)"}
    import boto3

    from . import agent
    from .config import StackConfig

    cfg = StackConfig(
        region=os.environ.get("AWS_REGION", "us-east-1"),
        prefix=os.environ.get("CHKP_PREFIX", ""),
    )
    session = boto3.Session()
    opt = payload if isinstance(payload, dict) else {}
    return agent.run_task_captured(
        cfg, session, task,
        model=os.environ.get("CHKP_MODEL") or None,
        session_id=opt.get("sessionId"),
        actor=opt.get("actor"),
    )


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, obj):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):  # quiet the default stderr access log
        pass

    def do_GET(self):
        if self.path.rstrip("/") == "/ping" or self.path == "/":
            self._send(200, {"status": "Healthy"})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path.rstrip("/") != "/invocations":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, UnicodeDecodeError) as e:
            self._send(400, {"error": f"invalid JSON body: {e}"})
            return
        try:
            result = run_invocation(payload)
        except Exception as e:  # noqa: BLE001 -- never crash the runtime worker
            self._send(500, {"error": f"{type(e).__name__}: {str(e)[:300]}"})
            return
        self._send(200, result)


def main():  # pragma: no cover -- exercised only inside the container
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"chkpmcpaws hosted agent listening on :{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":  # pragma: no cover
    main()
