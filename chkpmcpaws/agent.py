"""A Check Point security-operations agent.

Claude (on Amazon Bedrock) reasons over your Check Point estate; every tool
call it makes goes THROUGH the MCP gateway, so the AI guardrail (when it is
enforcing) governs each one. That is the full chain in one command:

    agent  ->  Bedrock Converse (Claude)  ->  MCP gateway (guardrail)  ->  @chkp tools

One agent loop, two deployment targets (the `--runtime` flag):
  local      run the loop in THIS process. Field-tested; the recommended demo.
  agentcore  host the identical loop on an AgentCore Runtime. Live-validated
             (like the guardrail) -- see _run_agentcore below.

Model calls use boto3's `bedrock-runtime` Converse API -- the AWS-native
tool-use surface -- so boto3 stays the only hard dependency (the `mcp` package
is required for the gateway client, same optional dep the rest of the CLI uses).

Model selection: Bedrock model access is granted per-model per-account, so
there is no single id that works everywhere. With no --model, the agent
auto-selects the first model this account can actually call from MODEL_PREFERENCE
(a capable Claude first, cheap fallbacks after). --model forces a specific id.
There is no free Bedrock tier; Amazon Nova Micro is the cheapest option.
"""

import asyncio
import json
import re
import sys
import time

from . import cognito as cog
from . import mcpcheck
from . import memory as mem_mod
from .awsutil import (
    BotoCoreError,
    ClientError,
    agentcore_client,
    err_code,
    has_log_sink,
    log,
    paginate,
    resolve_account,
)
from .ui import (
    BOLD,
    C_A,
    C_ERR,
    C_MUTED,
    C_OK,
    C_WARN,
    DIM,
    RESET,
    _grad,
    _rgb,
    _tty_ui_wanted,
)

# Preference order for auto-selection (no --model): a capable Claude first,
# then cheaper Claude, then Amazon Nova (cheapest last). Access is per-account,
# so the agent probes these in order and uses the first it can actually call.
MODEL_PREFERENCE = [
    "us.anthropic.claude-sonnet-4-6",
    "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "us.amazon.nova-lite-v1:0",
    "us.amazon.nova-micro-v1:0",
]
CHEAPEST_MODEL = "us.amazon.nova-micro-v1:0"
MAX_TURNS = 12
MAX_TOKENS = 2048

SYSTEM_PROMPT = (
    "You are a Check Point security-operations assistant. You help SOC analysts "
    "and administrators understand a Check Point estate by calling the Check Point "
    "MCP tools available to you (management objects, gateways, access rules, "
    "threat-prevention posture, logs). Tool names are namespaced <target>___<tool>, "
    "e.g. quantummanagement___show_hosts.\n\n"
    "Prefer read-only/investigative tools. Call a tool when the answer depends on "
    "live estate data rather than answering from memory. When you have enough to "
    "answer, answer -- concisely, leading with the outcome.\n\n"
    "GROUNDING RULES (follow exactly):\n"
    "1. COUNTS AND FACTS come only from tool output. When you report a count, use "
    "the exact number the tool returned -- the `total` field or the 'X of Y total' "
    "line -- and quote it. Never estimate, round, or infer a count. If a listing is "
    "paginated, the `total` is the count, not the number of items on one page.\n"
    "2. NAMING/UID-REQUIRED tools: some tools (e.g. show_access_rulebase) require an "
    "exact layer/rulebase name or uid. FIRST call the discovery tool "
    "(e.g. show_access_layers) to get the real names, then call the detail tool with "
    "a name/uid from that result. Do NOT guess names like 'Default Access Rules'.\n"
    "3. EMPTY RESULTS: a filtered query returning 0 items does NOT prove the thing "
    "doesn't exist -- your filter syntax or field name may be wrong. Retry without "
    "the filter (or with corrected fields) before concluding absence.\n"
    "4. TOOL FAILURE = NO ANSWER. If the tools error, get rate-limited (HTTP 429), "
    "or otherwise do not return the data, SAY you could not retrieve it and stop. "
    "Do NOT fall back to general knowledge or describe a 'typical' or 'common' "
    "configuration. A plausible-but-unverified security posture is WORSE than "
    "'I could not retrieve this.' Never state a fact -- a count, hostname, IP, rule "
    "name, OR a qualitative claim like 'IPS is enabled' / 'anti-bot is configured' "
    "-- that a tool did not actually return in this session.\n"
    "5. HOW-TO vs. MY-ESTATE -- pick the right KIND of tool first:\n"
    "   - 'How do I...', 'how to configure', 'what are the steps', 'best practice', "
    "or anything asking for procedure/concepts/official documentation is a "
    "DOCUMENTATION question: use the documentation___ tools. Do NOT run an "
    "estate/CLI tool against a specific object, and do NOT ask the user for a "
    "gateway/object name -- a how-to question is not about one object.\n"
    "   - 'What is configured', 'how many', 'show/list/which' asks about THIS "
    "estate's live state: use the product tools (quantummanagement___, "
    "threatprevention___, httpsinspection___, managementlogs___, quantumgwcli___).\n"
    "   Then match topic to namespace within that kind (threat prevention -> "
    "threatprevention___, logs -> managementlogs___, etc.)."
)


# =============================================================================
# Entry point
# =============================================================================
def run(cfg, session, task, runtime="local", use_guardrail=False, model=None,
        session_id=None, actor=None):
    # Check Point AI Guardrail (Lakera): when it is the selected engine,
    # --guardrail means an INLINE pre-model screen (not the AgentCore-Policy
    # gateway route). A flagged prompt is blocked before any model/tool call;
    # otherwise the normal MCP gateway is used (the guardrail is satisfied here).
    if use_guardrail:
        from . import lakera

        if lakera.is_lakera():
            # Show WHAT is happening before the (network) screen so the wait
            # never looks frozen; flush so it lands before the blocking call.
            log(_c(C_MUTED, "guardrail  screening the prompt with Check Point AI Guardrail (Lakera)…"))
            sys.stdout.flush()
            try:
                flagged, label, detail = lakera.screen_prompt(task, cfg=cfg, session=session)
            except Exception as e:  # noqa: BLE001 -- a broken guardrail must never silently pass
                log(_c(C_ERR, f"Check Point AI Guardrail unreachable "
                              f"({type(e).__name__}: {str(e)[:160]})"))
                log(_c(C_MUTED, " Check LAKERA_API_KEY / LAKERA_PROJECT_ID "
                                "(env, or the chkp/lakera-guard secret)."))
                return 1
            if flagged:
                # A block is the guardrail SUCCEEDING -- present it as a security
                # win (green, not an error) and exit 0: the tool worked as intended.
                msg = (f"Prompt blocked by {label} (attack detected)"
                       + (f": {detail}." if detail else "."))
                for line in lakera.blocked_lines(msg):
                    log(_c(C_ERR, line))     # red = blocked/deny (firewall-style); still exit 0
                return 0
            log(_c(C_OK, f"guardrail  {label} — no attack detected, prompt allowed ✓"))
            use_guardrail = False  # satisfied inline -> use the normal MCP gateway
    if runtime == "agentcore":
        return _run_agentcore(cfg, session, task, use_guardrail=use_guardrail,
                              session_id=session_id, actor=actor)
    return _run_local(cfg, session, task, use_guardrail=use_guardrail, model=model,
                      session_id=session_id, actor=actor)


# =============================================================================
# Pure helpers (unit-tested -- no AWS/network)
# =============================================================================
def sanitize_tool_name(name, seen):
    """Bedrock tool names must match [a-zA-Z0-9_-]{1,64} and be unique within a
    request. MCP gateway names (quantummanagement___show_hosts) are usually fine
    but can exceed 64 chars; sanitize + de-dup, preserving a reversible map."""
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", name)[:64] or "tool"
    base, i = safe, 1
    while safe in seen:
        suffix = f"_{i}"
        safe = base[: 64 - len(suffix)] + suffix
        i += 1
    seen.add(safe)
    return safe


def _clean_schema(schema):
    """Bedrock wants inputSchema.json to be an object schema. MCP tool schemas
    already are; normalize the minimum so Converse never 400s on a missing type."""
    if not isinstance(schema, dict) or schema.get("type") != "object":
        return {"type": "object", "properties": {}}
    schema.setdefault("properties", {})
    return schema


def build_tool_config(specs):
    """specs: list of (name, description, input_schema). Returns
    (converse_tool_config, {bedrock_name: mcp_name})."""
    tools, name_map, seen = [], {}, set()
    for name, desc, schema in specs:
        safe = sanitize_tool_name(name, seen)
        name_map[safe] = name
        tools.append({
            "toolSpec": {
                "name": safe,
                "description": ((desc or name).strip() or name)[:1000],
                "inputSchema": {"json": _clean_schema(schema)},
            }
        })
    return {"tools": tools}, name_map


def message_text(message):
    """Concatenate the text blocks of a Converse output message."""
    return "".join(b["text"] for b in message.get("content", []) if "text" in b)


def tool_uses(message):
    """Return the toolUse blocks of a Converse output message."""
    return [b["toolUse"] for b in message.get("content", []) if "toolUse" in b]


def mcp_result_to_text(result):
    """Flatten an mcp CallToolResult into text for a Converse toolResult."""
    parts = []
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        parts.append(text if text is not None else str(block))
    return "\n".join(parts) if parts else "(no content)"


def first_aws_error(exc):
    """Pull the first ClientError/BotoCoreError out of a possibly-nested
    ExceptionGroup. The MCP client's anyio task group re-wraps errors raised
    inside it as a BaseExceptionGroup, so a Bedrock ClientError does NOT arrive
    as a bare ClientError -- without unwrapping it escapes as a raw traceback."""
    if isinstance(exc, (ClientError, BotoCoreError)):
        return exc
    for inner in getattr(exc, "exceptions", None) or []:
        found = first_aws_error(inner)
        if found:
            return found
    return None


def _model_denied(exc):
    """True when the account simply can't call this model yet -- access not
    granted, OR (Anthropic models) the required use-case form isn't submitted."""
    code = err_code(exc)
    s = str(exc).lower()
    if code in ("AccessDeniedException", "AccessDenied"):
        return True
    if "not authorized" in s or "not available for this account" in s:
        return True
    # Anthropic models return ResourceNotFoundException until the use-case
    # details form is submitted in the Bedrock console.
    if code == "ResourceNotFoundException" and (
        "use case" in s or "model access" in s or "not been submitted" in s
    ):
        return True
    return False


def _model_label(model):
    if "anthropic" in model or "claude" in model:
        return "Claude on Amazon Bedrock"
    if "nova" in model:
        return "Amazon Nova on Bedrock"
    return "Amazon Bedrock"


# Transient Bedrock errors worth retrying (model-side / capacity), as opposed to
# AccessDenied/Validation which are terminal and must surface immediately.
# modelStreamErrorException arrives MID-STREAM (EventStreamError, lowercase
# code) when a weak model emits an invalid ToolUse sequence -- live-observed
# with nova-lite; a retry usually succeeds.
TRANSIENT_CODES = {
    "ModelErrorException",
    "ModelTimeoutException",
    "ThrottlingException",
    "ServiceUnavailableException",
    "InternalServerException",
    "ModelStreamErrorException",
    "modelStreamErrorException",
}


def converse_with_retry(bedrock, attempts=3, base_delay=1.5, **kwargs):
    """bedrock.converse with bounded retry on transient/model-side errors.
    Runs in a worker thread (asyncio.to_thread), so time.sleep is fine.
    Terminal errors (AccessDenied, Validation, ...) raise on the first hit."""
    last = None
    for attempt in range(attempts):
        try:
            return bedrock.converse(**kwargs)
        except ClientError as e:
            last = e
            if err_code(e) in TRANSIENT_CODES and attempt < attempts - 1:
                time.sleep(base_delay * (attempt + 1))
                continue
            raise
    raise last  # pragma: no cover (loop always returns or raises)


def supports_prompt_caching(model):
    """Claude and Amazon Nova on Bedrock support prompt caching (cachePoint) in
    the SYSTEM block; gate on family so an exotic --model can't 400 the request."""
    m = model.lower()
    return "claude" in m or "anthropic" in m or "nova" in m


def supports_tool_caching(model):
    """Only Claude accepts a cachePoint inside toolConfig -- Nova rejects it with
    a ValidationException (live-verified), so the tool-schema cache is
    Claude-only. The tool block is the big win, but system caching still helps."""
    m = model.lower()
    return "claude" in m or "anthropic" in m


def reconstruct_stream(events, on_text=None):
    """Rebuild a Converse message from a ConverseStream event iterable -- PURE
    and unit-tested (no AWS). Returns (message, stop_reason, usage).

    Text deltas are emitted via on_text(delta) for live streaming; toolUse input
    arrives as partial-JSON deltas that are concatenated and parsed at the end.
    """
    blocks = {}  # index -> {"kind": "text"|"tool", "text": str} or {"tu":..,"input":str}
    stop_reason, usage = None, {}
    for event in events:
        if "contentBlockStart" in event:
            ev = event["contentBlockStart"]
            start = ev.get("start", {})
            if "toolUse" in start:
                blocks[ev["contentBlockIndex"]] = {
                    "kind": "tool", "tu": start["toolUse"], "input": ""}
        elif "contentBlockDelta" in event:
            ev = event["contentBlockDelta"]
            idx, delta = ev["contentBlockIndex"], ev["delta"]
            if "text" in delta:
                b = blocks.setdefault(idx, {"kind": "text", "text": ""})
                b["text"] += delta["text"]
                if on_text:
                    on_text(delta["text"])
            elif "toolUse" in delta and idx in blocks:
                blocks[idx]["input"] += delta["toolUse"].get("input", "")
        elif "messageStop" in event:
            stop_reason = event["messageStop"].get("stopReason")
        elif "metadata" in event:
            usage = event["metadata"].get("usage", {}) or {}
    content = []
    for idx in sorted(blocks):
        b = blocks[idx]
        if b["kind"] == "text":
            content.append({"text": b["text"]})
        else:
            try:
                args = json.loads(b["input"]) if b["input"].strip() else {}
            except ValueError:
                args = {}
            content.append({"toolUse": {
                "toolUseId": b["tu"]["toolUseId"], "name": b["tu"]["name"], "input": args}})
    return {"role": "assistant", "content": content}, stop_reason, usage


def stream_converse(bedrock, on_text=None, attempts=3, base_delay=1.5, **kwargs):
    """converse_stream with retry, then reconstruct the message. Returns
    (message, stop_reason, usage). The retry also covers MID-STREAM failures
    (EventStreamError subclasses ClientError) -- reconstruct_stream runs inside
    the try, so a stream that dies halfway is retried whole. If some text was
    already streamed to the user before the failure, a retry notice is emitted
    so the repeated text is explained."""
    last = None
    for attempt in range(attempts):
        emitted = {"any": False}

        def _emit(delta, _flag=emitted):
            _flag["any"] = True
            on_text(delta)

        try:
            resp = bedrock.converse_stream(**kwargs)
            return reconstruct_stream(resp["stream"], on_text=_emit if on_text else None)
        except ClientError as e:
            last = e
            if err_code(e) in TRANSIENT_CODES and attempt < attempts - 1:
                if emitted["any"] and on_text:
                    on_text("\n  … model stream error — retrying …\n")
                time.sleep(base_delay * (attempt + 1))
                continue
            raise
    raise last  # pragma: no cover


def robust_converse(bedrock, on_text=None, **kwargs):
    """stream_converse with a non-streaming fallback. Weak models (live-observed:
    nova-lite) can fail DETERMINISTICALLY to encode certain tool calls as a
    stream -- modelStreamErrorException on every attempt -- while the same
    request succeeds through plain converse. When that happens, do the turn
    non-streaming and emit the finished text through on_text so the display
    path stays uniform. Returns (message, stop_reason, usage)."""
    try:
        return stream_converse(bedrock, on_text, **kwargs)
    except ClientError as e:
        if err_code(e) not in ("modelStreamErrorException", "ModelStreamErrorException"):
            raise
        resp = converse_with_retry(bedrock, **kwargs)
        msg = resp["output"]["message"]
        if on_text:
            text = message_text(msg)
            if text.strip():
                on_text(text)
        return msg, resp.get("stopReason"), resp.get("usage", {}) or {}


# =============================================================================
# Model selection -- access is per-account, so probe for what actually works
# =============================================================================
# The distinct case where Claude is entitled to the account but Anthropic's
# one-time use-case form has not been submitted: the agreement is in place, yet
# INVOKE returns ResourceNotFoundException until the form is filed. Worth its own
# message so the fix (submit the form) is obvious instead of a silent Nova drop.
_USE_CASE_FORM_NOTE = (
    "auto-selected -- Claude is enabled for this account but Anthropic's one-time "
    "use-case form is not submitted, so it can't be invoked yet. Submit it in the "
    "Bedrock console (Model access -> Anthropic -> use case details), wait ~15 min, "
    "then re-run to get Claude."
)


def _access_reason(exc):
    """Classify a failed model ping. The unsubmitted Anthropic use-case form
    surfaces as a ResourceNotFoundException whose message says the use-case
    details 'have not been submitted' -- distinct from a plain access denial."""
    msg = str(exc).lower()
    if "use case" in msg or "use-case" in msg or "not been submitted" in msg:
        return "use-case-form"
    return "no-access"


def _model_callable(bedrock, model_id):
    """(callable, reason): can the account invoke this model (tiny Converse
    ping)? reason is None when callable, else 'use-case-form' or 'no-access'."""
    try:
        bedrock.converse(
            modelId=model_id,
            messages=[{"role": "user", "content": [{"text": "hi"}]}],
            inferenceConfig={"maxTokens": 8},
        )
        return True, None
    except (ClientError, BotoCoreError) as e:
        return False, _access_reason(e)


def _pick_model(bedrock, requested):
    """Return (model_id, note). Explicit --model is returned as-is (a denial
    then surfaces as a clean message). Otherwise probe MODEL_PREFERENCE in order
    and return the first callable -- common case is one tiny ping. When it has to
    fall back past a Claude that is entitled but blocked by the unsubmitted
    Anthropic use-case form, the note says exactly that (not a vague 'not
    enabled') so the fix is obvious."""
    if requested:
        return requested, None
    claude_form_blocked = False
    for i, mid in enumerate(MODEL_PREFERENCE):
        ok, reason = _model_callable(bedrock, mid)
        if ok:
            if i == 0:
                return mid, None
            if claude_form_blocked:
                return mid, _USE_CASE_FORM_NOTE
            return mid, "auto-selected (earlier preferences not enabled for this account)"
        if "anthropic" in mid and reason == "use-case-form":
            claude_form_blocked = True
    # Nothing callable -> return the lead; the real call yields the clean error.
    return MODEL_PREFERENCE[0], "none of the preferred models are enabled"


def _print_model_denied(bedrock, model):
    log(_c(C_ERR, f"Bedrock has not granted this account access to '{model}'."))
    usable = [m for m in MODEL_PREFERENCE if _model_callable(bedrock, m)[0]]
    if usable:
        log(" Models this account CAN call right now -- pass one with --model:")
        for m in usable:
            tag = ("  (cheapest)" if "nova-micro" in m
                   else "  (cheap)" if ("haiku" in m or "nova" in m) else "")
            log("   " + _c(C_OK, m) + _c(C_MUTED, tag))
    else:
        log(" No common models are enabled. Open the Bedrock console -> Model access")
        log(" and enable a model (Amazon Nova is cheapest; Anthropic Claude for quality).")
    if "anthropic" in model or "claude" in model:
        log(_c(C_MUTED, " Try enabling Claude automatically:  python3 -m chkpmcpaws models enable"))
        log(_c(C_MUTED, "   (deploy also does this). If the account needs Anthropic's one-time"))
        log(_c(C_MUTED, "   use-case form, that command says so -- submit it once in the console."))
    log(_c(C_MUTED, " Bedrock has no free tier; Amazon Nova Micro is the cheapest option."))


# =============================================================================
# Branded (line-based) agent output -- streams the reasoning/answer rather than
# taking over the screen: for an agent you want to READ the conversation.
# =============================================================================
def _hdr(region, model):
    label = _model_label(model)
    if not _tty_ui_wanted():
        log(f"=== chkpmcpaws agent · {label} ({model}) · {region} ===")
        return
    badge = _rgb(C_A) + f"[ AGENT · {region} ]" + RESET
    log("")
    log(" " + _grad("◆ chkpmcpaws") + BOLD + f"  ·  agent  ·  {label}" + RESET
        + "        " + badge)
    log(" " + _rgb(C_MUTED) + f"model {model}" + RESET)


def _c(color, text):
    return (_rgb(color) + text + RESET) if _tty_ui_wanted() else text


# =============================================================================
# Local runtime -- the field-tested path
# =============================================================================
def _run_local(cfg, session, task, use_guardrail=False, model=None,
               session_id=None, actor=None):
    region = cfg.region
    if not mcpcheck.mcp_available():
        log("The agent needs the 'mcp' package for the gateway client:")
        log("  python3 -m pip install mcp")
        return 1
    ac = agentcore_client(session, region)
    account_id = resolve_account(session, region)

    gateway_url, token = _gateway_and_token(cfg, session, ac, use_guardrail, account_id)
    if not gateway_url:
        return 1
    if not token:
        log("Could not obtain a Cognito token (hosted domain still propagating?). "
            "Wait a moment and retry, or run: python3 -m chkpmcpaws status")
        return 1

    bedrock = session.client("bedrock-runtime", region_name=region)
    # Access is per-account: an explicit --model is honored; otherwise pick the
    # first model this account can actually call (see _pick_model).
    model, note = _pick_model(bedrock, model)
    _hdr(region, model)
    if note:
        log(" " + _c(C_WARN, note))
    if not model.startswith("us.amazon.nova"):
        log(" " + _c(C_MUTED, f"cheaper option: --model {CHEAPEST_MODEL}  (no free tier on Bedrock)"))
    log(" " + _c(C_MUTED, "task: ") + BOLD + task + RESET
        + ("   " + _c(C_WARN, "(via guardrail gateway)") if use_guardrail else ""))

    # Memory (#1) is opt-in: only when --session is given. Provisions (or attaches
    # to) the AgentCore Memory, then recalls long-term facts relevant to this task.
    memory = _prepare_memory(cfg, session, account_id, region, task, session_id, actor)
    gaia_cb = _prepare_gaia(cfg, session)
    log("")

    try:
        out = asyncio.run(_agent_loop(bedrock, model, gateway_url, token, task, region,
                                      session=session, memory=memory, elicitation_cb=gaia_cb))
        rc = out["rc"]
    except BaseException as raw:  # noqa: BLE001 -- unwrap anyio's ExceptionGroup
        if isinstance(raw, KeyboardInterrupt):
            raise
        e = first_aws_error(raw)
        log("")
        if e is not None and _model_denied(e):
            _print_model_denied(bedrock, model)
        elif e is not None and err_code(e) in TRANSIENT_CODES:
            log(_c(C_ERR, f"The model kept erroring ({err_code(e)}) after retries."))
            log(" This is model-side, not your stack -- the tools/gateway are fine. Smaller")
            log(" models (e.g. Nova Lite) are weaker at multi-step tool use. Try a stronger")
            log(" model, or enable Claude:")
            log(_c(C_MUTED, "   python3 -m chkpmcpaws models enable   (deploy does this too;"))
            log(_c(C_MUTED, "   submit Anthropic's one-time use-case form in the console only if it asks),"))
            log(_c(C_MUTED, "   then re-run (the agent auto-prefers Claude)."))
        elif e is not None and "ValidationException" in str(e) and "model identifier" in str(e).lower():
            log(_c(C_ERR, "That model id isn't valid on this account/region.") +
                " Use the inference-profile form, e.g. --model " + MODEL_PREFERENCE[0])
        elif e is not None:
            detail = ""
            if isinstance(e, ClientError):
                detail = (e.response.get("Error", {}).get("Message") or "")[:300]
            log(_c(C_ERR, f"Bedrock call failed: {err_code(e) or e}")
                + (f"  --  {detail}" if detail else ""))
        else:
            log(_c(C_ERR, f"Agent error: {type(raw).__name__}: {str(raw)[:200]}"))
        return 1
    return rc


def _prepare_memory(cfg, session, account_id, region, task, session_id, actor):
    """Opt-in memory setup. Returns a dict {id, actor, session_id, prior} the
    loop uses to inject recalled context and save the turn -- or None when
    --session was not given or provisioning failed (agent stays stateless)."""
    if not session_id:
        return None
    log(" " + _c(C_MUTED, "memory: attaching AgentCore Memory (first run provisions it) ..."))
    mid = mem_mod.ensure_memory(cfg, session, account_id, region)
    if not mid:
        log(" " + _c(C_WARN, "memory: unavailable -- running stateless for this task."))
        return None
    who = mem_mod.sanitize_id(actor, mem_mod.ACTOR_DEFAULT)
    sid = mem_mod.sanitize_id(session_id, "default")
    prior = mem_mod.recall(session, region, mid, who, task)
    tail = "recalled prior context" if prior else "no prior facts yet"
    log(" " + _c(C_OK, f"memory on") + _c(C_MUTED, f"  ·  session {sid}  ·  actor {who}  ·  {tail}"))
    return {"id": mid, "actor": who, "session_id": sid, "prior": prior}


def _prepare_gaia(cfg, session):
    """Build the Gaia login elicitation callback if creds are configured, so the
    agent can answer the Gaia server's per-gateway login prompt. Returns None
    (silent) when unconfigured -- Gaia tools then behave as before."""
    from . import gaia
    creds = gaia.load_gaia_creds(session, cfg)
    cb = gaia.make_elicitation_callback(creds)
    if cb:
        # Honest: the AgentCore Gateway does not relay elicitation, so this only
        # fires in a direct-server topology (see chkpmcpaws.gaia).
        log(" " + _c(C_MUTED, "gaia login answerer armed (fires only if the MCP "
            "transport relays elicitation; the gateway currently does not)"))
    return cb


def run_task_captured(cfg, session, task, model=None, use_guardrail=False,
                      session_id=None, actor=None):
    """Run one task and RETURN the result dict (instead of an exit code). Used by
    the AgentCore-hosted server (chkpmcpaws._hosting_server) so the container reuses
    the EXACT same gateway+token+loop path as `agent --runtime local`."""
    region = cfg.region
    ac = agentcore_client(session, region)
    account_id = resolve_account(session, region)
    gateway_url, token = _gateway_and_token(cfg, session, ac, use_guardrail, account_id)
    if not gateway_url or not token:
        return {"result": "Could not reach the MCP gateway or mint a Cognito token.",
                "error": True}
    bedrock = session.client("bedrock-runtime", region_name=region)
    model, _ = _pick_model(bedrock, model)
    memory = _prepare_memory(cfg, session, account_id, region, task, session_id, actor)
    gaia_cb = _prepare_gaia(cfg, session)
    out = asyncio.run(_agent_loop(bedrock, model, gateway_url, token, task, region,
                                  session=session, memory=memory, elicitation_cb=gaia_cb))
    return {"result": out["answer"], "usage": out["usage"], "model": model, "error": False}


async def _agent_loop(bedrock, model, gateway_url, token, task, region,
                      session=None, memory=None, elicitation_cb=None):
    ClientSession, streamablehttp_client = mcpcheck._mcp_imports()
    async with streamablehttp_client(
        gateway_url, headers={"Authorization": f"Bearer {token}"}
    ) as (r, w, _):
        session_kwargs = {"elicitation_callback": elicitation_cb} if elicitation_cb else {}
        async with ClientSession(r, w, **session_kwargs) as mcp:
            await mcp.initialize()
            specs = await _list_specs(mcp)
            tool_config, name_map = build_tool_config(specs)

            # Prompt caching (#2): mark the big STATIC prefixes -- the system
            # prompt and (Claude only) the tool-schema block -- with a cachePoint
            # so every turn after the first (and repeat runs within the cache TTL)
            # reads them from cache instead of re-billing full input. The tool
            # block is by far the largest payload (hundreds of schemas under
            # --servers all) but Nova rejects a cachePoint there, so it is gated
            # separately (see supports_tool_caching).
            cache = supports_prompt_caching(model)
            system = [{"text": SYSTEM_PROMPT}]
            if cache:
                system.append({"cachePoint": {"type": "default"}})
                if supports_tool_caching(model):
                    tool_config = {"tools": tool_config["tools"]
                                   + [{"cachePoint": {"type": "default"}}]}
            # Recalled memory (#1) varies per task, so it goes AFTER the cachePoint
            # -- it must not invalidate the cached static prefix above.
            if memory and memory.get("prior"):
                system.append({"text": memory["prior"]})

            log(" " + _c(C_MUTED, f"{len(specs)} tools discovered through the gateway"
                + ("  ·  prompt caching on" if cache else "")))
            log("")

            # Live token streaming (#4): print assistant text as it arrives. Only
            # when log() isn't captured by the full-screen reporter -- otherwise
            # buffer and emit the whole line at block end (below).
            live = not has_log_sink()
            stream = {"open": False}

            def on_text(delta):
                if not stream["open"]:
                    sys.stdout.write(" " + _c(C_A, "assistant") + "  ")
                    stream["open"] = True
                sys.stdout.write(delta)
                sys.stdout.flush()

            # Token accounting (#5): sum usage across turns; cacheRead proves the
            # cache is working and is billed at a fraction of fresh input.
            totals = {"in": 0, "out": 0, "cache_read": 0, "cache_write": 0}
            usage_fields = (("in", "inputTokens"), ("out", "outputTokens"),
                            ("cache_read", "cacheReadInputTokens"),
                            ("cache_write", "cacheWriteInputTokens"))

            messages = [{"role": "user", "content": [{"text": task}]}]
            last_answer = ""
            for turn in range(MAX_TURNS):
                stream["open"] = False
                msg, stop_reason, usage = await asyncio.to_thread(
                    robust_converse,
                    bedrock,
                    on_text if live else None,
                    modelId=model,
                    system=system,
                    messages=messages,
                    toolConfig=tool_config,
                    inferenceConfig={"maxTokens": MAX_TOKENS},
                )
                if stream["open"]:
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                messages.append(msg)
                for key, field in usage_fields:
                    totals[key] += usage.get(field, 0) or 0

                text = message_text(msg)
                if text.strip():
                    last_answer = text.strip()
                    if not live:
                        log(" " + _c(C_A, "assistant") + "  " + text.strip())

                if stop_reason != "tool_use":
                    break

                results = []
                for tu in tool_uses(msg):
                    real = name_map.get(tu["name"], tu["name"])
                    args = tu.get("input") or {}
                    log(" " + _c(C_A, "→ tool") + f"  {real}  "
                        + _c(C_MUTED, json.dumps(args)[:120]))
                    outcome = await _call_one(mcp, real, args)
                    glyph = _c(C_ERR, "✗ error") if outcome["error"] else _c(C_OK, "✓ ok")
                    log("        " + glyph + "  " + _c(C_MUTED, outcome["text"][:140].replace("\n", " ")))
                    results.append({
                        "toolResult": {
                            "toolUseId": tu["toolUseId"],
                            "content": [{"text": outcome["text"][:6000]}],
                            "status": "error" if outcome["error"] else "success",
                        }
                    })
                messages.append({"role": "user", "content": results})
            else:
                log(" " + _c(C_WARN, f"stopped after {MAX_TURNS} turns (turn budget reached)"))

            # Persist this task + answer so long-term extraction learns from it
            # (best-effort; extraction runs asynchronously server-side).
            if memory and session is not None:
                saved = await asyncio.to_thread(
                    mem_mod.record_turn, session, region, memory["id"],
                    memory["actor"], memory["session_id"], task, last_answer)
                if saved:
                    log(" " + _c(C_MUTED, "memory: turn saved (facts extract asynchronously)"))

            log("")
            _log_usage(totals, cache)
            log(" " + (_grad("✔ done") if _tty_ui_wanted() else "done"))
            return {"rc": 0, "answer": last_answer, "usage": dict(totals)}


def _log_usage(totals, cache):
    """One-line token telemetry (#5). cacheRead/Write only shown when caching is
    on; the hit-rate makes the caching win visible run to run."""
    if not (totals["in"] or totals["out"]):
        return
    parts = [f"{totals['in']:,} in", f"{totals['out']:,} out"]
    if cache:
        parts.append(f"{totals['cache_read']:,} cache-read")
        if totals["cache_write"]:
            parts.append(f"{totals['cache_write']:,} cache-write")
    line = "tokens  " + "  ·  ".join(parts)
    seen_input = totals["cache_read"] + totals["in"]
    if cache and seen_input:
        pct = round(100 * totals["cache_read"] / seen_input)
        line += f"  ·  {pct}% of input from cache"
    log(" " + _c(C_MUTED, line))


async def _list_specs(mcp):
    specs, cur = [], None
    while True:
        res = await mcp.list_tools(cursor=cur)
        for t in res.tools:
            schema = getattr(t, "inputSchema", None) or {"type": "object", "properties": {}}
            specs.append((t.name, t.description or "", schema))
        cur = res.nextCursor
        if not cur:
            break
    return specs


async def _call_one(mcp, name, args):
    try:
        res = await mcp.call_tool(name, args)
        return {"text": mcp_result_to_text(res), "error": bool(getattr(res, "isError", False))}
    except Exception as e:  # tool/transport error -> report, keep the loop alive
        return {"text": f"tool call failed: {e}", "error": True}


# =============================================================================
# Gateway + token discovery (read-only; mirrors verify.py)
# =============================================================================
def _gateway_and_token(cfg, session, ac, use_guardrail, account_id):
    name = cfg.guardrail_gateway_name if use_guardrail else cfg.gateway_name
    gw_id = None
    for gw in paginate(ac.list_gateways):
        if gw.get("name") == name:
            gw_id = gw.get("gatewayId")
            break
    if not gw_id:
        hint = ("python3 -m chkpmcpaws guardrail provision" if use_guardrail
                else "python3 -m chkpmcpaws deploy")
        log(f"No gateway '{name}' found -- deploy it first:  {hint}")
        return None, None
    gateway_url = ac.get_gateway(gatewayIdentifier=gw_id).get("gatewayUrl")

    cognito = session.client("cognito-idp", region_name=cfg.region)
    pool_id = cog.find_pool(cognito, cfg.pool_name)
    client_id = cog.find_client(cognito, pool_id, cfg.app_client_name) if pool_id else None
    if not (pool_id and client_id):
        log(f"Cognito pool/client not found -- deploy the MCP tools first: python3 -m chkpmcpaws deploy")
        return gateway_url, None
    secret = cog.client_secret(cognito, pool_id, client_id)
    endpoint = cog.token_endpoint(cfg.cognito_domain(account_id), cfg.region)
    token = cog.get_token(endpoint, client_id, secret, f"{cfg.res_server}/read", attempts=6)
    return gateway_url, token


# =============================================================================
# AgentCore-hosted runtime -- live-validated (see chkpmcpaws.hosting).
# =============================================================================
def _run_agentcore(cfg, session, task, use_guardrail=False, session_id=None, actor=None):
    """Host the identical loop on an AgentCore Runtime and InvokeAgentRuntime it.
    DOCS-DERIVED (see chkpmcpaws.hosting) -- first run builds the image + runtime."""
    from . import hosting

    log("")
    log(_c(C_A, "◆ chkpmcpaws agent · --runtime agentcore") + "  (AWS-native hosting)")
    log(" " + _c(C_MUTED, "uses the runtime the deploy provisioned; if it is "
        "missing (deploy --no-agent), this builds it now (several minutes)."))
    if use_guardrail:
        log(" " + _c(C_WARN, "note: --guardrail routing is a local-runtime feature; "
            "the hosted path uses the standard gateway."))
    log("")

    # Preflight: the hosted agent reasons over your estate THROUGH the gateway,
    # so bail out BEFORE the multi-minute container build if the MCP tools stack
    # (gateway) isn't deployed -- otherwise we'd build a runtime that has nothing
    # to reach and only discover it at invoke time.
    ac = agentcore_client(session, cfg.region)
    gw_name = cfg.guardrail_gateway_name if use_guardrail else cfg.gateway_name
    if not any(gw.get("name") == gw_name for gw in paginate(ac.list_gateways)):
        log(_c(C_ERR, f"No gateway '{gw_name}' found -- deploy the MCP tools stack first:"))
        log(_c(C_OK, "   python3 -m chkpmcpaws deploy"))
        log(" " + _c(C_MUTED, "then re-run this. (Skipped the container build -- nothing "
            "to connect to yet.)"))
        return 1

    result, err = hosting.invoke(cfg, session, task, session_id=session_id, actor=actor)
    if err:
        log(_c(C_ERR, "Hosted run failed:"))
        for line in err:
            log("  " + line)
        log("")
        log(" " + _c(C_MUTED, "The field-tested local runtime is unaffected:"))
        log(_c(C_OK, f'   python3 -m chkpmcpaws chat "{task}"'))
        return 1

    result = result or {}
    # The HTTP invoke can succeed while the agent itself could not complete
    # (e.g. gateway/token/model problem inside the runtime): honor result.error
    # instead of reporting a green "done".
    if result.get("error"):
        log(_c(C_ERR, "Hosted agent could not complete the task:"))
        log("  " + str(result.get("result") or "unknown error"))
        log("")
        log(" " + _c(C_MUTED, "The runtime is up; this is a data-path issue. Check the "
            "gateway/estate with:  python3 -m chkpmcpaws status"))
        return 1

    answer = result.get("result", "")
    usage = result.get("usage") or {}
    log(" " + _c(C_A, "assistant") + "  " + str(answer).strip())
    if usage:
        _log_usage({"in": usage.get("in", 0), "out": usage.get("out", 0),
                    "cache_read": usage.get("cache_read", 0),
                    "cache_write": usage.get("cache_write", 0)},
                   cache=True)
    log("")
    log(" " + (_grad("✔ done (hosted)") if _tty_ui_wanted() else "done (hosted)"))
    return 0
