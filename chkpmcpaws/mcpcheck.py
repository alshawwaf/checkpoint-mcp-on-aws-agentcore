"""MCP catalog checks through the gateway.

Preferred path uses the optional `mcp` package (full pagination, proper
initialize handshake). Fallback is a pure-stdlib JSON-RPC POST (first page
only). All HTTP goes through urllib with default TLS verification -- ON.
Bearer tokens are used in headers but never logged.
"""

import asyncio
import collections
import json
import urllib.error
import urllib.request

from .awsutil import log, tls_context


# =============================================================================
# Parsing
# =============================================================================
def extract_json_rpc(raw):
    """Parse a JSON-RPC body that may be plain JSON or SSE (text/event-stream).

    Returns a dict, or None if nothing dict-shaped is found (so callers can
    safely .get() the result without an AttributeError on scalar/array JSON).
    """
    raw = raw.strip()
    try:
        val = json.loads(raw)
        if isinstance(val, dict):
            return val
    except ValueError:
        pass
    # SSE framing: pull the last `data:` payload that parses as a JSON object.
    result = None
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            chunk = line[len("data:"):].strip()
            try:
                val = json.loads(chunk)
            except ValueError:
                continue
            if isinstance(val, dict):
                result = val
    return result


def summarize_tools(names, header="TOTAL TOOLS THROUGH THE GATEWAY"):
    """Log the per-target catalog summary and RETURN the lines (so a caller
    can also persist them in a Reporter summary)."""
    by = collections.Counter(n.split("___")[0] for n in names if "___" in n)
    lines = [f"{header}: {len(names)}"] + [f"  {k}: {v}" for k, v in sorted(by.items())]
    for ln in lines:
        log(ln)
    return lines


# =============================================================================
# Preferred path: the optional `mcp` package
# =============================================================================
def _mcp_imports():
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    return ClientSession, streamablehttp_client


def mcp_available():
    try:
        _mcp_imports()
        return True
    except ImportError:
        return False


def verify_tools_mcp(gateway_url, access_token):
    """Full paginated tools/list; logs the per-target summary and RETURNS the
    summary lines (so a caller can persist the catalog in a Reporter summary).

    Returns None if the `mcp` package is not installed -- a missing optional
    dependency never fails a deploy; callers treat None as "check skipped".
    """
    if not mcp_available():
        return None

    lines = []

    async def _run():
        ClientSession, streamablehttp_client = _mcp_imports()
        async with streamablehttp_client(
            gateway_url, headers={"Authorization": f"Bearer {access_token}"}
        ) as (r, w, _):
            async with ClientSession(r, w) as sess:
                await sess.initialize()
                names, cur = [], None
                while True:
                    result = await sess.list_tools(cursor=cur)
                    names += [t.name for t in result.tools]
                    cur = result.nextCursor
                    if not cur:
                        break
                lines.extend(summarize_tools(names))

    try:
        asyncio.run(_run())
    except Exception as exc:  # network/auth hiccup -> report, don't crash
        log(f"  tools/list attempt raised: {exc}")
    return lines


def call_tool_mcp(gateway_url, access_token, tool, arguments):
    """tools/call via the mcp package. Returns an outcome dict; raises
    ImportError if the package is missing (caller falls back to stdlib)."""
    ClientSession, streamablehttp_client = _mcp_imports()

    async def _run():
        async with streamablehttp_client(
            gateway_url, headers={"Authorization": f"Bearer {access_token}"}
        ) as (r, w, _):
            async with ClientSession(r, w) as sess:
                await sess.initialize()
                return await sess.call_tool(tool, arguments)

    try:
        result = asyncio.run(_run())
    except Exception as exc:
        return {"transport": "mcp", "outcome": "error", "detail": str(exc)}
    detail = ""
    try:
        detail = json.dumps(
            [getattr(c, "text", str(c)) for c in (result.content or [])]
        )[:600]
    except Exception:
        detail = str(result)[:600]
    outcome = "tool-error" if getattr(result, "isError", False) else "allowed"
    return {"transport": "mcp", "outcome": outcome, "detail": detail}


# =============================================================================
# Fallback path: pure stdlib JSON-RPC POST (first page / single call)
# =============================================================================
def post_jsonrpc(gateway_url, access_token, method, params=None):
    """POST one JSON-RPC message. Returns (http_status, parsed_dict_or_None,
    raw_text). TLS verification stays ON (awsutil.tls_context; falls back to
    the certifi/botocore CA bundle on an empty default trust store)."""
    msg = {"jsonrpc": "2.0", "id": "1", "method": method}
    if params is not None:
        msg["params"] = params
    req = urllib.request.Request(
        gateway_url,
        data=json.dumps(msg).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {access_token}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30, context=tls_context()) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return resp.status, extract_json_rpc(raw), raw
    except urllib.error.HTTPError as e:
        raw = ""
        try:
            raw = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        return e.code, extract_json_rpc(raw), raw
    except urllib.error.URLError as e:
        return None, None, str(e)


HTTP_HINTS = {
    401: "bad inbound token",
    403: "request rejected before the target (outbound SigV4 or policy deny)",
}


def list_tools_stdlib_first_page(gateway_url, access_token):
    """First-page tools/list without the mcp package; prints results/hints."""
    status, obj, raw = post_jsonrpc(gateway_url, access_token, "tools/list")
    if status not in (200, None) and not obj:
        hint = HTTP_HINTS.get(status, "")
        log(f"  HTTP {status} {('- ' + hint) if hint else ''}")
        return
    if status is None:
        log(f"  request failed: {raw}")
        return
    tools = obj.get("result", {}).get("tools") if isinstance(obj, dict) else None
    if not isinstance(tools, list):
        log("  Could not parse a tools/list result from the response. Raw (truncated):")
        log("  " + raw[:800])
        return
    names = [t.get("name", "") for t in tools if isinstance(t, dict)]
    summarize_tools(
        names, header="TOOLS ON THE FIRST PAGE (install 'mcp' for the full count)"
    )


def call_tool(gateway_url, access_token, tool, arguments):
    """tools/call preferring the mcp package, stdlib bare-POST fallback.

    Returns {transport, outcome, detail} where outcome is one of:
    allowed / tool-error / denied-or-error / error. Classification of a deny is
    best-effort (the exact gateway deny shape is environment-dependent); the
    raw detail is always included so the operator can read what happened.
    """
    try:
        return call_tool_mcp(gateway_url, access_token, tool, arguments)
    except ImportError:
        pass
    status, obj, raw = post_jsonrpc(
        gateway_url,
        access_token,
        "tools/call",
        {"name": tool, "arguments": arguments},
    )
    if status is None:
        return {"transport": "stdlib", "outcome": "error", "detail": raw}
    if isinstance(obj, dict) and "result" in obj:
        is_err = bool(obj["result"].get("isError")) if isinstance(obj["result"], dict) else False
        return {
            "transport": "stdlib",
            "outcome": "tool-error" if is_err else "allowed",
            "detail": json.dumps(obj["result"])[:600],
        }
    detail = ""
    if isinstance(obj, dict) and "error" in obj:
        detail = json.dumps(obj["error"])[:600]
    else:
        detail = f"HTTP {status}: {raw[:400]}"
    return {"transport": "stdlib", "outcome": "denied-or-error", "detail": detail}
