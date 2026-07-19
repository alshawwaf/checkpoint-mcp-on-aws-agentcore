# Scenario: Call the Hosted Agent from Anything

The hosted agent (`chkp_agent`, provisioned by `deploy`) is an HTTPS service. This runbook covers calling it from real client software — Postman, Microsoft Teams, n8n, curl, or your own applications — instead of the `chkpmcpaws` CLI.

Two paths, by client capability:

| Client can sign AWS SigV4? | Use |
|---|---|
| Yes (Postman, AWS SDKs, botocore, aws-curl) | **Direct**: `InvokeAgentRuntime` — no extra infrastructure |
| No (Teams / Power Automate, n8n, plain curl, webhooks) | **Bridge**: a bearer-token API Gateway endpoint — `chkpmcpaws bridge provision` |

Both return the same JSON shape:

```json
{"result": "There are 14 hosts configured...", "usage": {"in": 34824, "out": 99, "cache_read": 0, "cache_write": 50326}, "model": "us.amazon.nova-lite-v1:0", "error": false}
```

The bridge strips model scaffolding (`<thinking>` blocks) at the boundary, so consumers always see a clean answer.

## Worked example (end to end)

A real call and its response, through the bridge:

```bash
python3 -m chkpmcpaws bridge provision          # once; also runs as part of deploy setup
URL=$(python3 -m chkpmcpaws bridge show | awk '/URL/{print $3}')
TOKEN=$(aws secretsmanager get-secret-value --secret-id 'chkp/agent-bridge' \
  --query SecretString --output text | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')

curl -s -X POST "$URL" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"prompt": "How many access layers are configured and what are their names?", "session": "demo"}'
```

Response (real output from the deployed stack):

```json
{
  "result": "There are 3 access layers configured in the estate:\n1. DNS_Layer\n2. dynamic_layer\n3. Network",
  "usage": {"in": 20478, "out": 127, "cache_read": 22283, "cache_write": 40579},
  "model": "us.amazon.nova-lite-v1:0",
  "error": false
}
```

That is the whole professional pattern: an application POSTs a plain-English question with a bearer token, the hosted agent runs the full reason → gateway → Check Point tools loop server-side, and returns a grounded JSON answer with per-request token usage. No CLI, no AWS SDK in the caller. The identical call from an AWS-aware client (Postman) uses Path 1 below and needs no bridge.

## Path 1 — Direct SigV4 (Postman and AWS-aware clients)

The AgentCore data plane is a plain REST API:

```text
POST https://bedrock-agentcore.us-east-1.amazonaws.com/runtimes/<URL-ENCODED-RUNTIME-ARN>/invocations?qualifier=DEFAULT
Content-Type: application/json
X-Amzn-Bedrock-AgentCore-Runtime-Session-Id: <any string of 33+ chars>

{"prompt": "how many hosts are configured?"}
```

Signed with **AWS Signature Version 4**, service name `bedrock-agentcore`. Get the exact ready-to-paste URL (runtime ARN already encoded) from:

```
python3 -m chkpmcpaws bridge show
```

**Postman setup:** import [collateral/Check-Point-MCP-Agent.postman_collection.json](../../collateral/Check-Point-MCP-Agent.postman_collection.json) — the "direct SigV4" request has the auth pre-configured (type *AWS Signature*, service `bedrock-agentcore`); fill in your access key, secret key, and session token as collection variables. The caller needs IAM permission `bedrock-agentcore:InvokeAgentRuntime` on the runtime.

## Path 2 — The bridge (Teams, n8n, curl, anything)

```
python3 -m chkpmcpaws bridge provision
python3 -m chkpmcpaws bridge show --reveal-token
```

`provision` creates a REGIONAL API Gateway endpoint backed by a small Lambda (`chkp-agent-bridge`), a scoped execution role, and a random bearer token stored in AWS Secrets Manager (`chkp/agent-bridge`) — the token never appears in code or logs. Every request must carry it:

```
TOKEN=$(aws secretsmanager get-secret-value --secret-id 'chkp/agent-bridge' --query SecretString --output text | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
curl -s -X POST 'https://<api-id>.execute-api.us-east-1.amazonaws.com/prod' \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"prompt": "how many hosts are configured?", "session": "curl-demo"}'
```

Request body fields: `prompt` (required; `task`/`text`/`question` accepted as aliases), `session` (optional — groups turns for AgentCore Memory recall), `actor` (optional — per-analyst memory namespace).

Operational notes:

- **Rotate the token** by writing a new value to the secret; the Lambda picks it up within five minutes. `bridge provision` never overwrites an existing token.
- **Timeout**: the integration timeout is raised to 180 s where the account allows (provision falls back to API Gateway's classic 29 s cap and warns if not — long multi-tool questions can exceed 29 s).
- **Teardown**: `chkpmcpaws bridge destroy`, and the main `chkpmcpaws destroy` removes it too.
- Design note: the bridge fronts the Lambda with API Gateway rather than a Lambda Function URL — anonymous Function URL invokes were platform-rejected (HTTP 403) on the validation account, and NONE-auth URLs reserve the `Authorization` header for SigV4. API Gateway has neither restriction.

## Microsoft Teams (via Power Automate)

No Azure bot registration needed — a Power Automate flow turns any Teams message into an agent question:

1. In Teams, open **Workflows** (Power Automate) and create a flow with the trigger **"When someone responds to an adaptive card"** or, simpler, **"For a selected message"** (lets you right-click any message → run the flow on it).
2. Add an **HTTP** action:
   - Method `POST`, URI = the bridge URL
   - Headers: `Authorization` = `Bearer <token>`, `Content-Type` = `application/json`
   - Body: `{"prompt": "<message text dynamic content>", "session": "teams-demo"}`
3. Add **"Post message in a chat or channel"** and set the message to the HTTP action's `body('HTTP')?['result']`.

Store the token in a Power Automate **environment variable (secret)** or Azure Key Vault reference — not inline in the flow definition, per credential-handling policy.

Timing: agent answers typically take 10–60 seconds; the HTTP action's default timeout accommodates this when the 180 s integration timeout is active.

## n8n

HTTP Request node: `POST`, the bridge URL, header `Authorization: Bearer <token>`, JSON body `{"prompt": "{{$json.question}}"}`. Chain it after a Webhook/Slack/Teams trigger and map `result` from the response into the reply.

## Authenticating to Gaia (the interactive-auth exception)

Most Check Point MCP servers take credentials as environment variables, so the deploy stores each server's key in Secrets Manager and the tools just work through the gateway. **Gaia is different, and it matters if you want to use it.**

The `@chkp/quantum-gaia-mcp` server reads no credential environment variables and accepts no credential tool-arguments. Its *only* auth path is interactive **MCP elicitation**: on the first Gaia tool call the server sends an `elicitation/create` request back to the MCP client asking for the gateway IP/port, then the Gaia admin username and password (cached ~15 minutes per gateway). This is confirmed in the server's own README ("The interactive authentication dialog will prompt for credentials through your MCP client interface") and its source (`packages/gaia/src/gaia-auth.ts`).

**Validated finding (2026-07-16): this cannot work through the AgentCore Gateway.** The gateway aggregates tools but does not relay `elicitation/create` back to the connecting client. So a Gaia tool call through our gateway — from the CLI agent, the hosted agent, the bridge, or Postman — receives no prompt to answer and simply hangs. The gateway address as a tool argument (`gateway_ip`, `port`) does not help: those satisfy the gateway-discovery prompt, but the username/password prompt still has no answerer. For that reason **quantum-gaia is excluded from the default deploy and from `--servers all`.**

If you have the gateway address and Gaia admin credentials and want to use Gaia today, run the server **directly** — outside our gateway — in an elicitation-capable MCP client:

```bash
# In Claude Desktop's MCP config (or any stdio MCP client), add:
#   command: npx   args: ["-y", "@chkp/quantum-gaia-mcp"]
# Ask a Gaia question; the client shows a login dialog; enter the
# gateway IP/port, then the admin user + password. Cached ~15 min.
```

Our repo carries the answerer for that topology: [chkpmcpaws/gaia.py](../../chkpmcpaws/gaia.py) fills the elicitation from a `chkp/quantum-gaia` secret (set it with `chkpmcpaws creds template` / `apply`, the `[quantum-gaia]` section) or `GAIA_*` env vars. It is wired into the agent's MCP client and is correct — it just never fires through the AgentCore Gateway, which doesn't forward the prompt. It becomes live automatically in a direct-server topology, or through the gateway the day AWS relays elicitation.

The clean fix is on Check Point's side: give the Gaia server an environment-variable / non-interactive credential path like every other `@chkp` server has. Until then, Gaia is a direct-client server, not a gateway server.

## Security model recap

- The bridge endpoint requires the bearer token on every call (constant-time compare in the Lambda; 401 otherwise) — no anonymous path.
- The Lambda's role can do exactly two things: read that one secret, and `InvokeAgentRuntime` on the one agent runtime.
- Everything downstream is unchanged: the agent authenticates to the MCP gateway with a Cognito machine-to-machine token, the gateway signs to runtimes with SigV4, and each server reads only its own credentials secret.
- For production, front the bridge with your standard API management (per-user auth, rate limits, WAF) or skip the bridge and have your application sign SigV4 directly with per-service IAM roles.
