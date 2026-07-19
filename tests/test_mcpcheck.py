"""The SSE/JSON-RPC response parser must never hand a non-dict to callers."""

from chkpmcpaws.mcpcheck import extract_json_rpc


def test_plain_json_object():
    assert extract_json_rpc('{"jsonrpc":"2.0","result":{"tools":[]}}') == {
        "jsonrpc": "2.0",
        "result": {"tools": []},
    }


def test_sse_framing_takes_last_data_object():
    raw = (
        "event: message\n"
        'data: {"jsonrpc":"2.0","id":"0","result":{"partial":true}}\n'
        "\n"
        "event: message\n"
        'data: {"jsonrpc":"2.0","id":"1","result":{"tools":[{"name":"a___b"}]}}\n'
    )
    obj = extract_json_rpc(raw)
    assert obj["result"]["tools"][0]["name"] == "a___b"


def test_sse_ignores_non_json_data_lines():
    raw = 'data: not-json\ndata: {"ok": true}\n'
    assert extract_json_rpc(raw) == {"ok": True}


def test_scalar_and_array_json_return_none():
    assert extract_json_rpc("42") is None
    assert extract_json_rpc('["a","b"]') is None
    assert extract_json_rpc("") is None
    assert extract_json_rpc("<html>gateway error</html>") is None


def test_summarize_tools_returns_lines():
    from chkpmcpaws.mcpcheck import summarize_tools
    lines = summarize_tools(["t___a", "t___b", "u___c"], header="TOTAL")
    assert lines[0] == "TOTAL: 3"
    assert "  t: 2" in lines and "  u: 1" in lines
