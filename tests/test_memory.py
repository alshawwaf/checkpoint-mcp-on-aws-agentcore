"""Pure-logic tests for AgentCore Memory helpers (no AWS)."""

import re

from chkpmcpaws.memory import (
    ACTOR_DEFAULT,
    STRATEGY_NAME,
    build_event_payload,
    memory_strategies,
    namespace_for,
    records_to_context,
    sanitize_id,
)


def test_sanitize_id_charset_and_fallback():
    # an email is coerced into the allowed actorId charset
    assert sanitize_id("kalshaww@checkpoint.com", ACTOR_DEFAULT) == "kalshaww-checkpoint-com"
    # empty / all-illegal falls back
    assert sanitize_id("", "fb") == "fb"
    assert sanitize_id("   ", "fb") == "fb"
    assert sanitize_id("!!!", "fb") == "fb"
    # legal id passes through
    assert sanitize_id("analyst_1", "fb") == "analyst_1"
    # capped at 128 and leading/trailing separators stripped
    assert sanitize_id("-x-", "fb") == "x"
    assert len(sanitize_id("a" * 300, "fb")) == 128
    # every result is a legal actorId/sessionId
    for raw in ("a b", "user@x.io", "société", "id/with/slash"):
        assert re.fullmatch(r"[a-zA-Z0-9_-]+", sanitize_id(raw, "fb"))


def test_namespace_for():
    assert namespace_for("chkp-analyst") == "/chkp/chkp-analyst"
    assert namespace_for("{actorId}") == "/chkp/{actorId}"


def test_memory_strategies_shape():
    strat = memory_strategies()
    assert len(strat) == 1
    sem = strat[0]["semanticMemoryStrategy"]
    assert sem["name"] == STRATEGY_NAME
    # namespace template must carry the {actorId} placeholder so recall lines up
    assert sem["namespaces"] == ["/chkp/{actorId}"]


def test_build_event_payload_variants():
    both = build_event_payload("q?", "a.")
    assert [b["conversational"]["role"] for b in both] == ["USER", "ASSISTANT"]
    assert both[0]["conversational"]["content"]["text"] == "q?"
    # only a task (no answer yet)
    assert [b["conversational"]["role"] for b in build_event_payload("q?", "")] == ["USER"]
    # only an answer
    assert [b["conversational"]["role"] for b in build_event_payload("  ", "a")] == ["ASSISTANT"]
    # nothing worth saving
    assert build_event_payload("", "   ") == []


def test_build_event_payload_strips_model_scaffolding():
    """Nova wraps reasoning in <thinking> and the answer in <response> -- only
    the clean answer should reach long-term extraction."""
    raw = "<thinking>I need to retry the call.</thinking>\n\n<response>There are 42 hosts.</response>"
    payload = build_event_payload("how many hosts?", raw)
    texts = [b["conversational"]["content"]["text"] for b in payload]
    assert texts == ["how many hosts?", "There are 42 hosts."]
    # answer that is ONLY thinking noise -> nothing saved for the assistant
    only_noise = build_event_payload("q?", "<thinking>hmm</thinking>")
    assert [b["conversational"]["role"] for b in only_noise] == ["USER"]


def test_records_to_context_orders_and_truncates():
    summaries = [
        {"content": {"text": "low"}, "score": 0.1},
        {"content": {"text": "high"}, "score": 0.9},
        {"content": {"text": "mid"}, "score": 0.5},
    ]
    ctx = records_to_context(summaries)
    assert ctx.startswith("PRIOR CONTEXT")
    # highest score first
    assert ctx.index("high") < ctx.index("mid") < ctx.index("low")
    # each fact rendered as a bullet
    assert "- high" in ctx and "- mid" in ctx


def test_records_to_context_char_budget():
    summaries = [{"content": {"text": "x" * 100}, "score": i} for i in range(50)]
    ctx = records_to_context(summaries, max_chars=250)
    # only as many facts as fit the budget (~2-3 of the 100-char facts)
    assert ctx.count("\n- ") <= 3


def test_records_to_context_empty():
    assert records_to_context([]) == ""
    assert records_to_context([{"content": {"text": "   "}, "score": 1}]) == ""
    assert records_to_context([{"score": 1}]) == ""  # no content key


# --- create-race recovery (two concurrent `agent --session` runs) -------------
class _RacingCtl:
    """First find sees nothing; CreateMemory then fails (another run won the
    race); the re-find sees the winner's memory, already ACTIVE."""

    def __init__(self):
        self.finds = 0

    def list_memories(self, **kw):
        self.finds += 1
        return {"memories": [] if self.finds == 1 else [{"id": "mem-won"}]}

    def get_memory(self, memoryId):
        return {"memory": {"id": memoryId, "name": "chkp_mcp_memory",
                           "status": "ACTIVE", "arn": "arn:x"}}

    def create_memory(self, **kw):
        from chkpmcpaws.awsutil import ClientError
        raise ClientError({"Error": {"Code": "ValidationException",
                                     "Message": "memory name already exists"}},
                          "CreateMemory")

    create_event = None  # hasattr(ctl, "create_memory") gate uses create_memory


def test_ensure_memory_attaches_after_losing_create_race(monkeypatch):
    import chkpmcpaws.memory as mem
    from chkpmcpaws.config import StackConfig
    ctl = _RacingCtl()
    monkeypatch.setattr(mem, "agentcore_client", lambda session, region: ctl)
    monkeypatch.setattr(mem, "ensure_memory_role", lambda *a, **kw: "arn:role")
    monkeypatch.setattr(mem.time, "sleep", lambda *_: None)
    mid = mem.ensure_memory(StackConfig(), session=None, account_id="1" * 12,
                            region="us-east-1")
    assert mid == "mem-won"  # attached to the winner instead of failing


class _PropagationCtl:
    """CreateMemory fails twice (fresh exec role not assumable yet -- IAM
    propagation), then succeeds. find_memory always sees nothing."""

    def __init__(self):
        self.creates = 0

    def list_memories(self, **kw):
        return {"memories": []}

    def get_memory(self, memoryId):
        return {"memory": {"id": memoryId, "name": "chkp_mcp_memory",
                           "status": "ACTIVE", "arn": "arn:x"}}

    def create_memory(self, **kw):
        from chkpmcpaws.awsutil import ClientError
        self.creates += 1
        if self.creates < 3:
            raise ClientError({"Error": {"Code": "ValidationException",
                                         "Message": "role is not assumable"}},
                              "CreateMemory")
        return {"memory": {"id": "mem-new"}}


def test_ensure_memory_retries_role_propagation(monkeypatch):
    import chkpmcpaws.memory as mem
    from chkpmcpaws.config import StackConfig
    ctl = _PropagationCtl()
    monkeypatch.setattr(mem, "agentcore_client", lambda session, region: ctl)
    monkeypatch.setattr(mem, "ensure_memory_role", lambda *a, **kw: "arn:role")
    monkeypatch.setattr(mem.time, "sleep", lambda *_: None)
    mid = mem.ensure_memory(StackConfig(), session=None, account_id="1" * 12,
                            region="us-east-1")
    assert mid == "mem-new" and ctl.creates == 3  # retried through propagation
