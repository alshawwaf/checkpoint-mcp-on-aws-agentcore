"""AgentCore Memory for the security-ops agent -- OPT-IN via `agent --session`.

Introspection/docs-derived: every request shape here is built against the boto3
`bedrock-agentcore` (data plane) and `bedrock-agentcore-control` (control plane)
service models, but the round-trip has NOT been validated against a live account
yet -- see the VALIDATE-LIVE notes below. It is kept entirely OFF the field-tested
default agent path: with no --session, the agent behaves exactly as before and
never touches this module.

Two AWS-native layers:
  short-term   each turn's user question + final answer is written as a
               conversational Event (CreateEvent), scoped to (actorId, sessionId).
  long-term    a SEMANTIC memory strategy extracts durable facts from those
               events into a per-actor namespace; the next task recalls the most
               relevant of them (RetrieveMemoryRecords) and injects them as
               PRIOR CONTEXT for the model.

Lifecycle:
  ensure_memory()   find-or-create the Memory (+ its execution role), wait ACTIVE
  record_turn()     best-effort CreateEvent after a task (never raises)
  recall()          best-effort RetrieveMemoryRecords before a task (never raises)
  delete_memory()   remove the Memory + role (called by `destroy`)
  describe()        status for `verify`

LIVE-VALIDATED (2026-07-16, account 342469737784 / us-east-1): CreateMemory with
the semantic strategy + 90-day expiry + execution role reached ACTIVE (~3-5 min);
find-or-attach on re-run; RetrieveMemoryRecords on the {actorId} namespace (empty
pre-extraction); CreateEvent persisted USER+ASSISTANT payloads (ListEvents
confirmed); DeleteMemory via destroy. Still to observe: extracted long-term
records appearing after the async extraction pass and being recalled into a
later session's PRIOR CONTEXT.
"""

import re
import time
from datetime import datetime, timezone

from .awsutil import (
    ClientError,
    agentcore_client,
    agentcore_data_client,
    err_code,
    log,
    paginate,
)

# The strategy name is stable so its namespace template is predictable.
STRATEGY_NAME = "chkpFacts"
ACTOR_DEFAULT = "chkp-analyst"
EVENT_EXPIRY_DAYS = 90
RECALL_TOP_K = 5
RECALL_MAX_CHARS = 1500


# =============================================================================
# Pure helpers (unit-tested -- no AWS)
# =============================================================================
def sanitize_id(value, fallback):
    """actorId / sessionId accept letters, digits, hyphen, underscore; must be
    non-empty. Coerce anything else (e.g. an email) into that charset."""
    safe = re.sub(r"[^a-zA-Z0-9_-]", "-", (value or "").strip())
    safe = safe.strip("-") or fallback
    return safe[:128]


def namespace_for(actor):
    """Per-actor long-term namespace. The strategy stores facts under the same
    template with {actorId} resolved, so recall reads the concrete path."""
    return f"/chkp/{actor}"


def memory_strategies():
    """A single semantic (fact-extraction) strategy scoped per actor."""
    return [
        {
            "semanticMemoryStrategy": {
                "name": STRATEGY_NAME,
                "description": "Durable Check Point estate facts learned across sessions.",
                "namespaces": [namespace_for("{actorId}")],
            }
        }
    ]


def build_event_payload(task, answer):
    """A conversational Event: the user's question + the agent's final answer.
    Empty text blocks are dropped (CreateEvent rejects empty content). Model
    scaffolding tags (Nova's <thinking>/<response>) are stripped so long-term
    extraction learns from the answer, not the reasoning noise."""
    answer = re.sub(r"<thinking>.*?</thinking>", "", answer or "", flags=re.S)
    answer = re.sub(r"</?response>", "", answer)
    payload = []
    if (task or "").strip():
        payload.append({"conversational": {"role": "USER", "content": {"text": task.strip()}}})
    if answer.strip():
        payload.append(
            {"conversational": {"role": "ASSISTANT", "content": {"text": answer.strip()}}}
        )
    return payload


def records_to_context(summaries, max_chars=RECALL_MAX_CHARS):
    """Format retrieved memory records into a PRIOR CONTEXT block for the system
    prompt. Highest-scoring first; truncated to a budget so recall can't crowd
    out the task. Returns '' when there is nothing to inject."""
    facts = []
    for s in sorted(summaries, key=lambda r: r.get("score") or 0, reverse=True):
        text = ((s.get("content") or {}).get("text") or "").strip()
        if text:
            facts.append(text)
    if not facts:
        return ""
    lines, used = [], 0
    for f in facts:
        if used + len(f) > max_chars:
            break
        lines.append(f"- {f}")
        used += len(f)
    if not lines:
        return ""
    return (
        "PRIOR CONTEXT (recalled from memory of earlier sessions; may be stale -- "
        "verify with a tool before relying on it, and never present it as a "
        "freshly-confirmed fact):\n" + "\n".join(lines)
    )


# =============================================================================
# Lookups
# =============================================================================
def find_memory(ctl, name):
    """MemorySummary carries no name, so read each with GetMemory and match.
    Returns {'id','status','arn'} or None. Small accounts only -- fine here."""
    for summ in paginate(ctl.list_memories):
        mid = summ.get("id")
        if not mid:
            continue
        try:
            mem = ctl.get_memory(memoryId=mid).get("memory", {})
        except ClientError:
            continue
        if mem.get("name") == name:
            return {"id": mem.get("id"), "status": mem.get("status"), "arn": mem.get("arn")}
    return None


# =============================================================================
# Execution role (assumed by AgentCore Memory to run long-term extraction)
# =============================================================================
def ensure_memory_role(cfg, session, account_id, region):
    import json

    iam = session.client("iam")
    name = cfg.memory_role
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "MemoryAssumeRole",
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    perms = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "InvokeExtractionModel",
                "Effect": "Allow",
                "Action": ["bedrock:InvokeModel"],
                "Resource": [
                    f"arn:aws:bedrock:{region}::foundation-model/*",
                    f"arn:aws:bedrock:{region}:{account_id}:inference-profile/*",
                ],
            }
        ],
    }
    try:
        iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=json.dumps(trust),
            Tags=cfg.tags_kv(),
        )
    except ClientError as e:
        if err_code(e) != "EntityAlreadyExists":
            raise
    iam.put_role_policy(
        RoleName=name, PolicyName="MemoryExtractionExec", PolicyDocument=json.dumps(perms)
    )
    return f"arn:aws:iam::{account_id}:role/{name}"


# =============================================================================
# Lifecycle
# =============================================================================
def ensure_memory(cfg, session, account_id, region):
    """Find-or-create the Memory and its role, wait for ACTIVE, return memoryId.
    Returns None (with a logged reason) on any failure -- memory is an
    enhancement, so the agent degrades to its normal stateless behavior."""
    ctl = agentcore_client(session, region)
    if not hasattr(ctl, "create_memory"):
        log(" memory: this boto3 predates AgentCore Memory -- skipping (upgrade boto3).")
        return None

    existing = find_memory(ctl, cfg.memory_name)
    if existing and existing["status"] == "ACTIVE":
        return existing["id"]
    if existing and existing["status"] in ("CREATING", "UPDATING"):
        return _wait_active(ctl, existing["id"])
    if existing and existing["status"] == "FAILED":
        log(" memory: existing memory is FAILED; leaving it for you to inspect/destroy.")
        return None
    if existing and existing["status"] == "DELETING":
        # A destroy (or console delete) is still draining; same-name creation
        # would fail until it finishes -- wait it out (mirrors the Cognito
        # hosted-domain teardown->redeploy race).
        log(" memory: previous memory is still deleting -- waiting for it to finish ...")
        if not _wait_gone(ctl, existing["id"]):
            log(" memory: still deleting -- running stateless; retry in a few minutes.")
            return None

    try:
        role_arn = ensure_memory_role(cfg, session, account_id, region)
    except ClientError as e:
        log(f" memory: could not create the execution role ({err_code(e) or e}) -- skipping.")
        return None

    last = None
    for attempt in range(4):
        try:
            resp = ctl.create_memory(
                name=cfg.memory_name,
                description="Check Point security-ops agent memory (chkpmcpaws).",
                eventExpiryDuration=EVENT_EXPIRY_DAYS,
                memoryExecutionRoleArn=role_arn,
                memoryStrategies=memory_strategies(),
                tags=cfg.tags(),
            )
            return _wait_active(ctl, resp.get("memory", {}).get("id"))
        except ClientError as e:
            last = e
            # Lost a create race: a concurrent agent run already created the
            # same-named memory -- attach to the winner instead of giving up.
            again = find_memory(ctl, cfg.memory_name)
            if again and again["status"] in ("ACTIVE", "CREATING", "UPDATING"):
                log(" memory: another run is provisioning it -- attaching to that one.")
                return _wait_active(ctl, again["id"])
            # A just-created execution role may not be assumable yet (IAM
            # propagation, live-observed right after a destroy recreated the
            # role) -- retry before giving up.
            if attempt < 3:
                time.sleep(10)
    log(f" memory: CreateMemory failed ({err_code(last) or last}) -- continuing without memory.")
    return None


def _wait_gone(ctl, memory_id, attempts=36, delay=5):
    """Poll until a DELETING memory is actually gone (GetMemory raises
    NotFound). True when gone; False if it is still draining after ~3 min."""
    for _ in range(attempts):
        try:
            ctl.get_memory(memoryId=memory_id)
        except ClientError:
            return True
        time.sleep(delay)
    return False


def _wait_active(ctl, memory_id, attempts=75, delay=5):
    """Poll GetMemory until ACTIVE. Returns the id when active, else None.
    First-time provisioning is slow (live-observed ~3-5 minutes for a memory
    with a semantic strategy), hence the generous budget (~6 min)."""
    if not memory_id:
        return None
    for _ in range(attempts):
        try:
            status = ctl.get_memory(memoryId=memory_id).get("memory", {}).get("status")
        except ClientError:
            return None
        if status == "ACTIVE":
            return memory_id
        if status in ("FAILED", "DELETING"):
            log(f" memory: memory entered {status} while provisioning -- skipping.")
            return None
        time.sleep(delay)
    log(" memory: still provisioning (continues server-side) -- this task runs "
        "stateless; re-run with --session in a few minutes and it will attach.")
    return None


def delete_memory(cfg, session, region):
    """Remove the Memory and its execution role. Idempotent; returns a short
    status string for the destroy plan/report."""
    ctl = agentcore_client(session, region)
    removed = []
    if hasattr(ctl, "create_memory"):
        found = find_memory(ctl, cfg.memory_name)
        if found:
            try:
                ctl.delete_memory(memoryId=found["id"])
                removed.append(f"memory {cfg.memory_name}")
            except ClientError as e:
                log(f" memory: DeleteMemory failed ({err_code(e) or e}).")
    iam = session.client("iam")
    try:
        iam.delete_role_policy(RoleName=cfg.memory_role, PolicyName="MemoryExtractionExec")
    except ClientError:
        pass
    try:
        iam.delete_role(RoleName=cfg.memory_role)
        removed.append(f"role {cfg.memory_role}")
    except ClientError:
        pass
    return ", ".join(removed) if removed else None


def describe(cfg, session, region):
    """For `verify`: {'present': bool, 'status': str|None, 'id': str|None}."""
    try:
        ctl = agentcore_client(session, region)
        if not hasattr(ctl, "create_memory"):
            return {"present": False, "status": None, "id": None}
        found = find_memory(ctl, cfg.memory_name)
    except ClientError:
        found = None
    if not found:
        return {"present": False, "status": None, "id": None}
    return {"present": True, "status": found["status"], "id": found["id"]}


# =============================================================================
# Per-task data-plane calls (best-effort -- never raise into the agent loop)
# =============================================================================
def recall(session, region, memory_id, actor, query, top_k=RECALL_TOP_K):
    """Retrieve the most relevant long-term facts for this task. Returns a
    PRIOR CONTEXT string ('' if none / on any error)."""
    if not memory_id:
        return ""
    try:
        data = agentcore_data_client(session, region)
        resp = data.retrieve_memory_records(
            memoryId=memory_id,
            namespace=namespace_for(actor),
            searchCriteria={"searchQuery": query, "topK": top_k},
            maxResults=top_k,
        )
    except ClientError:
        return ""
    return records_to_context(resp.get("memoryRecordSummaries") or [])


def record_turn(session, region, memory_id, actor, session_id, task, answer):
    """Persist the task + answer as a conversational Event so long-term
    extraction can learn from it. Best-effort; returns True on success."""
    if not memory_id:
        return False
    payload = build_event_payload(task, answer)
    if not payload:
        return False
    try:
        data = agentcore_data_client(session, region)
        data.create_event(
            memoryId=memory_id,
            actorId=actor,
            sessionId=session_id,
            eventTimestamp=datetime.now(timezone.utc),
            payload=payload,
        )
        return True
    except ClientError as e:
        log(f" memory: could not save this turn ({err_code(e) or e}).")
        return False
