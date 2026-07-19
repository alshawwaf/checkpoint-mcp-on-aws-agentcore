"""Pure-logic tests for the agent's Bedrock<->MCP translation layer (no AWS)."""

from chkpmcpaws.agent import (
    MODEL_PREFERENCE,
    build_tool_config,
    first_aws_error,
    message_text,
    reconstruct_stream,
    sanitize_tool_name,
    stream_converse,
    supports_prompt_caching,
    tool_uses,
    _clean_schema,
    _model_denied,
    _pick_model,
)
from chkpmcpaws.awsutil import ClientError


def test_sanitize_tool_name_charset_and_length():
    seen = set()
    # legal MCP name passes through unchanged
    assert sanitize_tool_name("quantummanagement___show_hosts", seen) == "quantummanagement___show_hosts"
    # illegal chars replaced
    assert sanitize_tool_name("weird name!/v2", set()) == "weird_name__v2"
    # capped at 64
    long = "x" * 80
    assert len(sanitize_tool_name(long, set())) == 64


def test_sanitize_tool_name_dedup():
    seen = set()
    a = sanitize_tool_name("dup", seen)
    b = sanitize_tool_name("dup", seen)
    assert a == "dup" and b == "dup_1" and a != b


def test_build_tool_config_maps_back_to_mcp_names():
    specs = [
        ("quantummanagement___show_hosts", "List hosts", {"type": "object", "properties": {"limit": {"type": "integer"}}}),
        ("bad name/x", "", {}),
    ]
    cfg, name_map = build_tool_config(specs)
    assert len(cfg["tools"]) == 2
    # every bedrock name resolves back to the real MCP name
    for tool in cfg["tools"]:
        safe = tool["toolSpec"]["name"]
        assert name_map[safe] in ("quantummanagement___show_hosts", "bad name/x")
    # description falls back to the name when empty
    bad = next(t for t in cfg["tools"] if name_map[t["toolSpec"]["name"]] == "bad name/x")
    assert bad["toolSpec"]["description"] == "bad name/x"
    # schema always an object with properties
    assert bad["toolSpec"]["inputSchema"]["json"] == {"type": "object", "properties": {}}


def test_clean_schema_normalizes_non_object():
    assert _clean_schema({"type": "string"}) == {"type": "object", "properties": {}}
    assert _clean_schema(None) == {"type": "object", "properties": {}}
    ok = {"type": "object", "properties": {"a": {"type": "string"}}}
    assert _clean_schema(ok) is ok


def test_message_text_and_tool_uses():
    msg = {
        "role": "assistant",
        "content": [
            {"text": "Let me check. "},
            {"toolUse": {"toolUseId": "t1", "name": "show_hosts", "input": {"limit": 5}}},
            {"text": "one moment."},
        ],
    }
    assert message_text(msg) == "Let me check. one moment."
    tus = tool_uses(msg)
    assert len(tus) == 1 and tus[0]["name"] == "show_hosts" and tus[0]["input"] == {"limit": 5}


# --- the traceback bug: a Bedrock error re-wrapped by anyio's task group ------
def _access_denied():
    return ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "not available for this account"}},
        "Converse",
    )


def test_first_aws_error_unwraps_nested_exception_group():
    ce = _access_denied()
    outer = BaseExceptionGroup("tg", [BaseExceptionGroup("tg", [ce])])
    found = first_aws_error(outer)
    assert found is ce and _model_denied(found)


def test_first_aws_error_none_for_unrelated():
    assert first_aws_error(BaseExceptionGroup("x", [ValueError("nope")])) is None
    assert first_aws_error(RuntimeError("bare")) is None


# --- per-account model selection ---------------------------------------------
def _use_case_error():
    return ClientError(
        {"Error": {"Code": "ResourceNotFoundException",
                   "Message": "Model use case details have not been submitted for this account."}},
        "Converse",
    )


class _StubBedrock:
    def __init__(self, allowed, errors=None):
        self.allowed, self.calls = set(allowed), []
        self.errors = dict(errors or {})  # modelId -> zero-arg exception factory

    def converse(self, modelId, **kw):
        self.calls.append(modelId)
        if modelId in self.errors:
            raise self.errors[modelId]()
        if modelId not in self.allowed:
            raise _access_denied()
        return {"output": {"message": {"content": []}}}


def test_pick_model_honors_explicit_without_probing():
    b = _StubBedrock(allowed=[])
    assert _pick_model(b, "us.anthropic.claude-opus-4-8") == ("us.anthropic.claude-opus-4-8", None)
    assert b.calls == []


def test_pick_model_first_callable_wins_single_probe():
    b = _StubBedrock(allowed=set(MODEL_PREFERENCE))
    mid, note = _pick_model(b, None)
    assert mid == MODEL_PREFERENCE[0] and note is None and b.calls == [MODEL_PREFERENCE[0]]


def test_pick_model_falls_back_when_first_denied():
    b = _StubBedrock(allowed=[MODEL_PREFERENCE[1]])
    mid, note = _pick_model(b, None)
    assert mid == MODEL_PREFERENCE[1] and "auto-selected" in note


def test_pick_model_flags_use_case_form_when_claude_blocked():
    # Every Claude is entitled-but-blocked by the unsubmitted use-case form; the
    # agent falls back to a Nova, but the note must name the real fix (the form).
    claude = [m for m in MODEL_PREFERENCE if "anthropic" in m]
    nova = next(m for m in MODEL_PREFERENCE if "nova" in m)
    b = _StubBedrock(allowed=[nova], errors={m: _use_case_error for m in claude})
    mid, note = _pick_model(b, None)
    assert mid == nova
    assert "use-case form" in note and "Bedrock console" in note


def test_pick_model_prefers_sonnet_4_6():
    # Sonnet 4.6 leads the preference list (newer than 4.5).
    assert MODEL_PREFERENCE[0] == "us.anthropic.claude-sonnet-4-6"


# --- transient-error retry (nova's ModelErrorException) ----------------------
def _err(code):
    return ClientError({"Error": {"Code": code, "Message": code}}, "Converse")


class _FlakyBedrock:
    def __init__(self, fail_codes):
        self.fail_codes = list(fail_codes)  # raised in order, then success
        self.calls = 0

    def converse(self, **kw):
        self.calls += 1
        if self.fail_codes:
            raise _err(self.fail_codes.pop(0))
        return {"output": {"message": {"content": []}}, "stopReason": "end_turn"}


def test_converse_retries_transient_then_succeeds(monkeypatch):
    import chkpmcpaws.agent as agent
    monkeypatch.setattr(agent.time, "sleep", lambda *_: None)  # no real backoff
    b = _FlakyBedrock(["ModelErrorException", "ThrottlingException"])
    resp = agent.converse_with_retry(b, attempts=3)
    assert resp["stopReason"] == "end_turn"
    assert b.calls == 3  # two failures + one success


def test_converse_does_not_retry_access_denied(monkeypatch):
    import chkpmcpaws.agent as agent
    monkeypatch.setattr(agent.time, "sleep", lambda *_: None)
    b = _FlakyBedrock(["AccessDeniedException"])
    try:
        agent.converse_with_retry(b, attempts=3)
        assert False, "should have raised"
    except ClientError as e:
        from chkpmcpaws.awsutil import err_code
        assert err_code(e) == "AccessDeniedException"
    assert b.calls == 1  # terminal error: no retry


def test_converse_gives_up_after_attempts(monkeypatch):
    import chkpmcpaws.agent as agent
    monkeypatch.setattr(agent.time, "sleep", lambda *_: None)
    b = _FlakyBedrock(["ModelErrorException"] * 5)
    try:
        agent.converse_with_retry(b, attempts=3)
        assert False, "should have raised after exhausting attempts"
    except ClientError:
        pass
    assert b.calls == 3


# --- prompt-caching gates (#2) -----------------------------------------------
def test_supports_prompt_caching_by_family():
    assert supports_prompt_caching("us.anthropic.claude-sonnet-4-5-20250929-v1:0")
    assert supports_prompt_caching("us.anthropic.claude-haiku-4-5-20251001-v1:0")
    assert supports_prompt_caching("us.amazon.nova-micro-v1:0")
    assert supports_prompt_caching("CLAUDE")  # case-insensitive
    # an unknown/exotic family must NOT get a cachePoint (would 400)
    assert not supports_prompt_caching("meta.llama3-8b-instruct-v1:0")
    assert not supports_prompt_caching("mistral.mistral-large-2402-v1:0")


def test_tool_caching_is_claude_only():
    """Nova rejects a cachePoint inside toolConfig with a ValidationException
    (live-verified) -- the tool-schema cache must be gated to Claude."""
    from chkpmcpaws.agent import supports_tool_caching
    assert supports_tool_caching("us.anthropic.claude-sonnet-4-5-20250929-v1:0")
    assert not supports_tool_caching("us.amazon.nova-lite-v1:0")
    assert not supports_tool_caching("us.amazon.nova-micro-v1:0")
    assert not supports_tool_caching("meta.llama3-8b-instruct-v1:0")


# --- ConverseStream reconstruction (#4) --------------------------------------
def _text_stream(chunks, stop="end_turn", usage=None):
    """Build a text-only ConverseStream event list."""
    events = [{"messageStart": {"role": "assistant"}},
              {"contentBlockStart": {"contentBlockIndex": 0, "start": {}}}]
    events += [{"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"text": c}}}
               for c in chunks]
    events += [{"contentBlockStop": {"contentBlockIndex": 0}},
               {"messageStop": {"stopReason": stop}}]
    if usage is not None:
        events.append({"metadata": {"usage": usage}})
    return events


def test_reconstruct_stream_text_and_callback():
    seen = []
    msg, stop, usage = reconstruct_stream(
        _text_stream(["Hel", "lo, ", "world"], usage={"inputTokens": 10, "outputTokens": 3}),
        on_text=seen.append,
    )
    assert message_text(msg) == "Hello, world"
    assert msg["role"] == "assistant"
    assert stop == "end_turn"
    assert usage == {"inputTokens": 10, "outputTokens": 3}
    assert "".join(seen) == "Hello, world"  # streamed in order, no loss


def test_reconstruct_stream_tooluse_partial_json():
    """toolUse input arrives as partial-JSON deltas that must be joined + parsed,
    and the reconstructed toolUse must be readable by tool_uses()."""
    events = [
        {"messageStart": {"role": "assistant"}},
        {"contentBlockStart": {"contentBlockIndex": 0, "start": {}}},
        {"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"text": "Checking"}}},
        {"contentBlockStop": {"contentBlockIndex": 0}},
        {"contentBlockStart": {"contentBlockIndex": 1,
                               "start": {"toolUse": {"toolUseId": "t1", "name": "show_hosts"}}}},
        {"contentBlockDelta": {"contentBlockIndex": 1, "delta": {"toolUse": {"input": '{"lim'}}}},
        {"contentBlockDelta": {"contentBlockIndex": 1, "delta": {"toolUse": {"input": 'it": 5}'}}}},
        {"contentBlockStop": {"contentBlockIndex": 1}},
        {"messageStop": {"stopReason": "tool_use"}},
        {"metadata": {"usage": {"inputTokens": 20, "cacheReadInputTokens": 100}}},
    ]
    msg, stop, usage = reconstruct_stream(events)
    assert stop == "tool_use"
    assert message_text(msg) == "Checking"
    tus = tool_uses(msg)
    assert len(tus) == 1
    assert tus[0] == {"toolUseId": "t1", "name": "show_hosts", "input": {"limit": 5}}
    assert usage["cacheReadInputTokens"] == 100


def test_reconstruct_stream_empty_tooluse_input():
    """A toolUse with no input deltas parses to {} (not a crash)."""
    events = [
        {"contentBlockStart": {"contentBlockIndex": 0,
                               "start": {"toolUse": {"toolUseId": "t9", "name": "ping"}}}},
        {"contentBlockStop": {"contentBlockIndex": 0}},
        {"messageStop": {"stopReason": "tool_use"}},
    ]
    msg, stop, _ = reconstruct_stream(events)
    assert tool_uses(msg)[0]["input"] == {}


class _StreamBedrock:
    """converse_stream stub: fails a few times, then yields an event stream."""
    def __init__(self, fail_codes, events):
        self.fail_codes = list(fail_codes)
        self.events = events
        self.calls = 0

    def converse_stream(self, **kw):
        self.calls += 1
        if self.fail_codes:
            raise _err(self.fail_codes.pop(0))
        return {"stream": iter(self.events)}


def test_stream_converse_retries_transient_then_reconstructs(monkeypatch):
    import chkpmcpaws.agent as agent
    monkeypatch.setattr(agent.time, "sleep", lambda *_: None)
    b = _StreamBedrock(["ModelErrorException"], _text_stream(["ok"], usage={"inputTokens": 1}))
    msg, stop, usage = stream_converse(b, None, attempts=3)
    assert message_text(msg) == "ok" and stop == "end_turn"
    assert b.calls == 2  # one failure + one success


def test_stream_converse_does_not_retry_terminal(monkeypatch):
    import chkpmcpaws.agent as agent
    monkeypatch.setattr(agent.time, "sleep", lambda *_: None)
    b = _StreamBedrock(["AccessDeniedException"], _text_stream(["x"]))
    try:
        stream_converse(b, None, attempts=3)
        assert False, "should have raised"
    except ClientError:
        pass
    assert b.calls == 1


class _MidStreamFlaky:
    """First stream dies MID-ITERATION with modelStreamErrorException (the
    live-observed nova-lite 'invalid ToolUse sequence' failure); the second
    attempt streams clean."""

    def __init__(self, good_events):
        self.good_events = good_events
        self.calls = 0

    def converse_stream(self, **kw):
        self.calls += 1
        if self.calls == 1:
            def dying():
                yield {"messageStart": {"role": "assistant"}}
                yield {"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"text": "par"}}}
                raise _err("modelStreamErrorException")
            return {"stream": dying()}
        return {"stream": iter(self.good_events)}


def test_stream_converse_retries_midstream_failure(monkeypatch):
    import chkpmcpaws.agent as agent
    monkeypatch.setattr(agent.time, "sleep", lambda *_: None)
    b = _MidStreamFlaky(_text_stream(["full answer"], usage={"outputTokens": 2}))
    seen = []
    msg, stop, usage = stream_converse(b, seen.append, attempts=3)
    assert b.calls == 2
    assert message_text(msg) == "full answer"  # reconstruction restarted clean
    assert stop == "end_turn"
    # the partial text was explained with a retry notice before the re-stream
    joined = "".join(seen)
    assert "par" in joined and "retrying" in joined and joined.endswith("full answer")


class _StreamDeadBedrock:
    """Streaming ALWAYS dies with the nova-lite invalid-ToolUse failure;
    plain converse succeeds -- the live-observed deterministic case."""

    def __init__(self):
        self.stream_calls, self.converse_calls = 0, 0

    def converse_stream(self, **kw):
        self.stream_calls += 1
        def dying():
            yield {"messageStart": {"role": "assistant"}}
            raise _err("modelStreamErrorException")
        return {"stream": dying()}

    def converse(self, **kw):
        self.converse_calls += 1
        return {"output": {"message": {"role": "assistant",
                                       "content": [{"text": "non-streamed answer"}]}},
                "stopReason": "end_turn", "usage": {"inputTokens": 5, "outputTokens": 3}}


def test_robust_converse_falls_back_to_non_streaming(monkeypatch):
    import chkpmcpaws.agent as agent
    monkeypatch.setattr(agent.time, "sleep", lambda *_: None)
    b = _StreamDeadBedrock()
    seen = []
    msg, stop, usage = agent.robust_converse(b, seen.append)
    assert b.stream_calls == 3 and b.converse_calls == 1  # exhausted, then fell back
    assert message_text(msg) == "non-streamed answer"
    assert stop == "end_turn" and usage["inputTokens"] == 5
    # the finished text still reached the display callback
    assert "".join(seen).endswith("non-streamed answer")


def test_robust_converse_reraises_other_errors(monkeypatch):
    import chkpmcpaws.agent as agent
    monkeypatch.setattr(agent.time, "sleep", lambda *_: None)
    b = _StreamBedrock(["AccessDeniedException"], [])
    try:
        agent.robust_converse(b, None)
        assert False, "should have raised"
    except ClientError as e:
        from chkpmcpaws.awsutil import err_code
        assert err_code(e) == "AccessDeniedException"


# --- token telemetry line (#5) -----------------------------------------------
def test_log_usage_reports_cache_hit_rate(capsys, monkeypatch):
    import chkpmcpaws.agent as agent
    # force plain (no ANSI) so the assertion is on text, not color codes
    monkeypatch.setattr(agent, "_tty_ui_wanted", lambda: False)
    agent._log_usage({"in": 200, "out": 50, "cache_read": 800, "cache_write": 0}, cache=True)
    out = capsys.readouterr().out
    assert "200 in" in out and "50 out" in out
    assert "800 cache-read" in out
    assert "80% of input from cache" in out  # 800 / (800+200)


def test_log_usage_omits_cache_when_off(capsys, monkeypatch):
    import chkpmcpaws.agent as agent
    monkeypatch.setattr(agent, "_tty_ui_wanted", lambda: False)
    agent._log_usage({"in": 100, "out": 10, "cache_read": 0, "cache_write": 0}, cache=False)
    out = capsys.readouterr().out
    assert "100 in" in out and "cache" not in out


def test_log_usage_silent_when_no_tokens(capsys):
    import chkpmcpaws.agent as agent
    agent._log_usage({"in": 0, "out": 0, "cache_read": 0, "cache_write": 0}, cache=True)
    assert capsys.readouterr().out == ""


# --- hosted runtime (_run_agentcore): preflight + honest error handling ------
class _HostCfg:
    region = "us-east-1"
    gateway_name = "chkp-mcp-gw"
    guardrail_gateway_name = "chkp-mcp-gw-guardrail"


def _wire_agentcore(monkeypatch, gateways, invoke_return):
    """Stub the AWS + hosting calls _run_agentcore makes; return the hosting stub."""
    import chkpmcpaws.agent as agent
    monkeypatch.setattr(agent, "agentcore_client",
                        lambda s, r: type("AC", (), {"list_gateways": lambda self, **k: {}})())
    monkeypatch.setattr(agent, "paginate", lambda fn: iter(gateways))
    import chkpmcpaws.hosting as hosting
    calls = {"invoke": 0}
    def invoke(cfg, session, task, session_id=None, actor=None):
        calls["invoke"] += 1
        return invoke_return
    monkeypatch.setattr(hosting, "invoke", invoke)
    return calls


def test_run_agentcore_preflights_missing_gateway(monkeypatch):
    import chkpmcpaws.agent as agent
    calls = _wire_agentcore(monkeypatch, gateways=[], invoke_return=({}, None))
    rc = agent._run_agentcore(_HostCfg(), session=None, task="q")
    assert rc == 1
    assert calls["invoke"] == 0  # bailed BEFORE the container build


def test_run_agentcore_honors_error_flag(monkeypatch):
    import chkpmcpaws.agent as agent
    gws = [{"name": "chkp-mcp-gw"}]
    _wire_agentcore(monkeypatch, gateways=gws,
                    invoke_return=({"result": "Could not reach the MCP gateway", "error": True}, None))
    rc = agent._run_agentcore(_HostCfg(), session=None, task="q")
    assert rc == 1  # in-agent failure is NOT reported as success


def test_run_agentcore_success(monkeypatch):
    import chkpmcpaws.agent as agent
    gws = [{"name": "chkp-mcp-gw"}]
    _wire_agentcore(monkeypatch, gateways=gws,
                    invoke_return=({"result": "14 hosts", "usage": {"in": 10, "out": 2},
                                    "error": False}, None))
    rc = agent._run_agentcore(_HostCfg(), session=None, task="q")
    assert rc == 0
