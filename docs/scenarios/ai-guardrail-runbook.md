# Scenario: AI Guardrail — AWS-native policy enforcement

This is the **hands-on companion** to the [AI guardrail design](ai-guardrail-design.md). It stands up a working, deterministic allow/deny guardrail at an AgentCore Gateway so you can *show* enforcement — using the **AWS-native** substrate (AgentCore Policy + Bedrock Guardrails-in-Policy).

> [!IMPORTANT]
> **Read this framing first.**
> - **Optional demo — not part of `deploy`.** The MCP tools stack (`chkpmcpaws deploy`) never provisions this. It's a separate, opt-in demonstration you run explicitly with `chkpmcpaws guardrail provision`.
> - **AWS-native engine only (in this runbook).** What this deploys is AWS's *own* Policy + Guardrails engine, shown to demonstrate the AgentCore gateway policy decision point. **It is NOT Check Point binding its signal into that gateway policy** — that specific runtime-protection integration is **Early Access** (announced, not GA); contact Check Point to join the EA, and don't present *the gateway binding* as shipping today. What *is* GA today is Check Point's own **AI Guardrail (Lakera Guard)** as an inline, client-side prompt screen in the CLI (`chkpmcpaws chat --guardrail --guardrail-provider lakera`) — a separate, shipping option distinct from this AWS-native gateway demo.
> - **One of two interchangeable engines — the customer's choice.** The guardrail is optional. This runbook demos the **AWS-native** engine (AgentCore Policy + Bedrock Guardrails), which is the **default** provider (`gateway`). The alternative is Check Point's own **AI Guardrail (Lakera Guard)** — one inline Guard API call, **identical on AWS and Azure** — a drop-in opt-in selected with `--guardrail-provider lakera`. Customers already invested in the cloud's native guardrail keep it as the default; customers wanting Check Point's own, unified-across-clouds engine opt into Lakera. Neither is forced.
> - **Grammar live-validated; runtime block still to confirm.** The Cedar/guardrails policy was originally docs-derived. Its grammar is now confirmed against a live engine — AWS's own policy generator emits the same shape and the policy reaches `ACTIVE`. The one piece still to verify end to end is that a prompt-injection call is actually **denied at runtime under ENFORCE** (that `chkpmcpaws guardrail test` after `chkpmcpaws guardrail enforce` confirms).
> - **Safe by construction.** It creates a **separate** gateway `chkp-mcp-gw-guardrail` and never touches your MCP tools gateway, roles, runtimes, Cognito, or secret. It defaults to **LOG_ONLY** (evaluates and logs a would-be decision, blocks nothing) and always creates a baseline `permit` before any enforcement.

## Prerequisites

- **MCP tools already deployed** (`python3 -m chkpmcpaws deploy`) — this reuses its Cognito pool/client (read-only, for the guardrail gateway's inbound JWT) and routes the guardrail target at the `chkp_quantum_management` runtime (read-only; never modified or deleted).
- Region **us-east-1** (Guardrails-in-Policy is GA only in `us-east-1`, `eu-west-2`, `eu-north-1`, `ap-southeast-2`, `ap-northeast-1`).
- Working AWS credentials in your shell (see [Preflight](go-live-and-operations.md#preflight)) and `pip install boto3`.

## What it creates (all isolated from MCP tools)

| Resource | Name |
|---|---|
| Policy engine | `chkp_guardrail_engine` |
| Baseline permit policy (`ACTIVE`) | `chkp_guardrail_baseline_permit` — `permit (principal, action, resource is AgentCore::Gateway);` |
| Guardrail forbid policy (prompt-injection) | `chkp_guardrail_block_prompt_injection` |
| Separate guardrail gateway (MCP / Custom-JWT) | `chkp-mcp-gw-guardrail` |
| Guardrail target → MCP tools runtime | `guardrailtarget` |
| Guardrail gateway execution role | `AgentCoreGatewayRoleGuardrail` |

## Run it

**1. Provision in LOG_ONLY (shadow — blocks nothing):**

```
python3 -m chkpmcpaws guardrail provision
```

(The MCP tools stack must already be deployed — `python3 -m chkpmcpaws deploy` first if it isn't; the guardrail target points at one of its runtimes.)

In order, it creates the guardrail IAM role, the policy engine, the baseline permit, the separate guardrail gateway (engine attached in `LOG_ONLY`) and its target, and — **last** — the guardrail policy (created after the target so the target's actions exist in the engine schema). Nothing is blocked yet: the engine evaluates each call and logs a would-be `ALLOW`/`DENY`. Your MCP tools stack is untouched.

> [!NOTE]
> The guardrail policy grammar is live-validated, so it should reach `ACTIVE`. If it doesn't, the most likely cause is a changed tool/target name; the provisioner prints the exact `reason:`, leaves the rest of the substrate up in LOG_ONLY, and self-heals a failed policy on the next run. Point the guardrail at a different tool without editing source via `CHKP_GUARD_ACTION="<target>___<tool>"`.

**2. Drive traffic through the guardrail gateway — scripted:**

```
python3 -m chkpmcpaws guardrail test
```

This mints a Cognito token (the same client-credentials flow `status` uses) and sends two MCP calls to the guardrail gateway: a benign `tools/list`, and a prompt-injection `tools/call` at the guarded action (`guardrailtarget___show_hosts`). In LOG_ONLY **both still pass** — the point is that the injection attempt was *recorded* as a would-be deny. The command reports what happened per probe and prints the exact CloudWatch places to look. (With placeholder Check Point credentials the tool itself may error *after* being allowed — what matters here is allowed-vs-denied at the gateway, not tool success.)

Or drive **real agent traffic** through the guardrail instead of the scripted probes — every tool call the agent makes then crosses the guardrail gateway and shows up in the same CloudWatch metrics/logs:

```
python3 -m chkpmcpaws chat --guardrail "how many hosts are configured?"
```

**3. Observe decisions in CloudWatch** (there is **no** Policy authoring screen in the AgentCore console — provisioning is CLI/SDK; the console's role here is observing):

- CloudWatch → **GenAI Observability** → AgentCore Gateway views, or
- CloudWatch → Metrics → namespace **`AWS/Bedrock-AgentCore`** → `AllowDecisions` / `DenyDecisions` (dimension `Mode=LOG_ONLY`), or
- CloudWatch Logs → span attribute `aws.agentcore.policy.authorization_decision = ALLOW|DENY` (requires gateway traces / Transaction Search).

**4. Flip to ENFORCE (opt-in) and show the block:**

```
python3 -m chkpmcpaws guardrail enforce
python3 -m chkpmcpaws guardrail test
```

This flips **only** the guardrail gateway to `ENFORCE` (it refuses if the baseline permit isn't `ACTIVE`). Re-running the test sends the same prompt-injection call: it should now be **blocked at the gateway before reaching the target**, while the benign `tools/list` still succeeds (the baseline permit lets it through). `DenyDecisions` rises with `Mode=ENFORCE`.

**5. Prove MCP tools is unaffected** — in the console, `chkp-mcp-gw` and its tools still work throughout.

**6. Tear down (guardrail resources only):**

```
python3 -m chkpmcpaws guardrail destroy
```

Or tear down BOTH AI guardrail and MCP tools in the safe order:

```
python3 -m chkpmcpaws destroy
```

Removes the policies → guardrail gateway + target → engine → role, in dependency order. `chkp-mcp-gw`, its Cognito, runtimes, and secret remain. Run this **before** any MCP tools teardown (MCP tools teardown deletes the runtime the guardrail target references) — or just use `python3 -m chkpmcpaws destroy`, which handles that ordering for you.

## The console surfaces (what to point at)

- **AgentCore console → Gateways**: show both `chkp-mcp-gw` (MCP tools, working) and `chkp-mcp-gw-guardrail` (the isolated guardrail gateway). There is no "Policy" nav item — policy authoring is API-only.
- **Main Bedrock console → Guardrails** *(optional context)*: show the detector categories (content filters incl. prompt attacks; sensitive-information/PII) that the in-policy `BedrockGuardrails::PromptAttack` safeguard draws on. Say aloud: in-policy guardrails invoke these categories inline; richer standalone guardrail features (denied topics, word filters, contextual grounding) are **not** available in-policy.
- **CloudWatch**: the real console path for showing the allow/deny decisions (above).

## Talk track (honesty guardrails)

- Enforcement *in this demo* is **AWS-native** (AgentCore Policy + Bedrock Guardrails-in-Policy) — the default provider. Check Point *binding its signal into this gateway policy* is the **roadmap / Early Access** item, not wired in today. Separately, Check Point's own **AI Guardrail (Lakera Guard)** already ships as an inline client-side screen (`--guardrail-provider lakera`) — optional, opt-in, and identical on AWS and Azure.
- **LOG_ONLY first, ENFORCE by explicit opt-in.** You tune against real traffic in shadow before blocking anything.
- **Safe by construction:** always a baseline `permit` before enforcing (an ENFORCE engine is default-deny, forbid-wins); a **separate** gateway, so the working MCP tools gateway is never attached, PUT-replaced, or black-holed.
- Guardrail verdicts are **non-deterministic ML confidence scores**; the surrounding Cedar allow/deny is deterministic. You can't mix a standard Cedar `when {}` with a `when guardrails {}` block.
- **Region-limited** to the five Guardrails-in-Policy regions; **no policy console** (CLI/SDK only); standalone Bedrock Guardrails ≠ in-policy guardrails.

## What was validated live

The whole substrate has been exercised end to end on a real account: engine, baseline permit, guardrail gateway + target, the guardrail policy reaching `ACTIVE`, and teardown.

The **guardrail policy grammar** was the one docs-uncertain piece, now resolved by running AWS's own `StartPolicyGeneration` against the live engine and matching its output. Three details are load-bearing:

- the resource must be **bound to the gateway**: `resource == AgentCore::Gateway::"<gateway-arn>"` (a bare `resource` is what produced `Cannot find Action in schema` — the action is only defined in the context of its gateway resource);
- the data-path is **`context.input.message`** (not `.prompt`);
- the **`["PROMPT_INJECTION"]` re-index** after `PromptAttack(...)` is required before `.confidenceScore`.

The action name is simply the gateway-namespaced MCP tool, `guardrailtarget___show_hosts`.

**Still to confirm on your account:** that the prompt-injection call is actually **denied at runtime under ENFORCE** — the policy is now schema-valid and `ACTIVE`, but end-to-end blocking (and that `context.input.message` is populated for a `tools/call`) is what step 4 verifies. See the `VALIDATE LIVE` section of [`chkpmcpaws/guardrail.py`](../../chkpmcpaws/guardrail.py).
