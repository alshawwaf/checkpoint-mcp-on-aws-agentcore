"""Answer the Gaia MCP server's login elicitation on the agent's behalf.

The published quantum-gaia server (github.com/CheckPointSW/mcp-servers,
packages/gaia/src/gaia-auth.ts) reads NO credential environment variables and
takes no credential tool-args. It authenticates per gateway by ELICITING the
details mid-call: an MCP `elicitation/create` request back to the client for
the gateway IP + port, then the Gaia admin user + password (cached ~15 min).

This module supplies an elicitation callback that fills each requested field
from credentials the operator provides, so an MCP client can authenticate to
Gaia non-interactively.

  ** IMPORTANT -- gateway limitation (validated 2026-07-16) **
  The AgentCore Gateway does NOT relay `elicitation/create` to the connecting
  client. So through OUR gateway, this callback never fires and a Gaia tool
  call hangs -- Gaia cannot authenticate via the hosted/gateway agent, period.
  quantum-gaia is therefore excluded from the default deploy. This answerer is
  correct and works in a DIRECT-SERVER topology (run @chkp/quantum-gaia-mcp
  over stdio in an elicitation-capable client, or point an MCP client straight
  at the runtime), and it becomes live through the gateway the day AWS relays
  elicitation. See docs/scenarios/invoke-from-anywhere.md.

Credentials come from (first hit wins):
  1. Secrets Manager secret chkp/quantum-gaia (JSON) -- works local AND hosted
  2. GAIA_GATEWAY_IP / GAIA_PORT / GAIA_USER / GAIA_PASSWORD env vars (local)

Set the secret via the creds workflow (the [quantum-gaia] section):
    chkpmcpaws creds template   # writes a [quantum-gaia] section
    chkpmcpaws creds apply      # writes chkp/quantum-gaia

Nothing here is logged; the password never leaves the elicitation response.
"""

import json
import os

from .awsutil import ClientError, err_code, log

# Map the fields a Gaia elicitation may request -> our credential keys. The
# server's schema uses names like gateway_ip / port / user / password / address
# (gaia-auth.ts); match case-insensitively and by common aliases.
_FIELD_ALIASES = {
    "gateway_ip": "GAIA_GATEWAY_IP", "gatewayip": "GAIA_GATEWAY_IP",
    "ip": "GAIA_GATEWAY_IP", "address": "GAIA_GATEWAY_IP", "host": "GAIA_GATEWAY_IP",
    "port": "GAIA_PORT",
    "user": "GAIA_USER", "username": "GAIA_USER",
    "password": "GAIA_PASSWORD", "pass": "GAIA_PASSWORD",
}


def load_gaia_creds(session, cfg):
    """Return {GAIA_GATEWAY_IP, GAIA_PORT, GAIA_USER, GAIA_PASSWORD} from the
    secret or env, or {} if not configured. Non-fatal on any error."""
    creds = {}
    try:
        sm = session.client("secretsmanager", region_name=cfg.region)
        raw = sm.get_secret_value(SecretId=cfg.secret_name("quantum-gaia"))["SecretString"]
        creds = {k: str(v) for k, v in json.loads(raw).items()}
    except (ClientError, ValueError, KeyError):
        creds = {}
    # env vars override / fill in (handy for a quick local run)
    for key in ("GAIA_GATEWAY_IP", "GAIA_PORT", "GAIA_USER", "GAIA_PASSWORD", "GAIA_ADDRESS"):
        if os.environ.get(key):
            creds[key.replace("GAIA_ADDRESS", "GAIA_GATEWAY_IP")] = os.environ[key]
    # drop unfilled placeholders so "configured?" checks are honest
    return {k: v for k, v in creds.items()
            if v and not str(v).startswith(("PLACEHOLDER", "REPLACE"))}


def is_configured(creds):
    """True when we have enough to answer a Gaia login (gateway + user + pass)."""
    return bool(creds.get("GAIA_GATEWAY_IP") and creds.get("GAIA_USER")
                and creds.get("GAIA_PASSWORD"))


def _value_for(field_name, schema_prop, creds):
    """Best value for one requested field, coercing to the schema's type."""
    key = _FIELD_ALIASES.get(field_name.lower().replace("-", "_").replace(" ", "_"))
    val = creds.get(key) if key else None
    if val is None:
        if field_name.lower() == "port":
            val = creds.get("GAIA_PORT", "443")
        else:
            return None
    if (schema_prop or {}).get("type") in ("integer", "number"):
        try:
            return int(str(val))
        except ValueError:
            return None
    return str(val)


def make_elicitation_callback(creds):
    """Build an MCP elicitation callback that answers Gaia login forms from
    `creds`. Accepts every requested field we can fill; declines (fails fast,
    never hangs) when we cannot. Returns None if no creds are configured, so
    the caller can leave the default 'not supported' behavior in place."""
    if not is_configured(creds):
        return None

    async def elicitation_callback(context, params):
        # Lazy imports so `mcp` stays an optional dependency of the package.
        from mcp.types import ElicitResult, ErrorData, INVALID_REQUEST

        schema = getattr(params, "requestedSchema", None)
        props = (schema or {}).get("properties", {}) if isinstance(schema, dict) \
            else getattr(schema, "properties", {}) or {}
        if not props:
            # URL-mode or schemaless elicitation -- nothing we can answer.
            return ErrorData(code=INVALID_REQUEST, message="unsupported elicitation")
        content, missing = {}, []
        for field, prop in props.items():
            val = _value_for(field, prop if isinstance(prop, dict) else {}, creds)
            if val is None:
                missing.append(field)
            else:
                content[field] = val
        required = (schema.get("required") if isinstance(schema, dict) else
                    getattr(schema, "required", None)) or list(props)
        if any(r in missing for r in required):
            # Can't satisfy the form -> decline so the tool errors instead of hanging.
            return ElicitResult(action="decline")
        return ElicitResult(action="accept", content=content)

    return elicitation_callback
