"""Check Point AI Guardrail (Lakera Guard) -- an inline pre-model prompt screen.

The Check Point-native guardrail option, identical to the Azure port: one POST
to the Guard API. Selected by CHKP_GUARDRAIL_PROVIDER=lakera; the DEFAULT AWS
guardrail stays the AWS-native AgentCore-Policy gateway (chkpmcpaws.guardrail),
which routes tool calls through a Cedar policy. When Lakera is the provider,
`chat --guardrail` screens the user prompt inline BEFORE any model/tool call --
a flagged prompt is blocked and never reaches Bedrock.

Credentials: LAKERA_API_KEY / LAKERA_PROJECT_ID come from the environment
(local runs + .env) or, when absent, the chkp/lakera-guard Secrets Manager
secret (the hosted runtime reads it with its execution role). TLS verification
stays at the requests default (ON, always -- org policy). The key is only sent
in the Authorization header, never logged.
"""

import json
import os

from .config import (
    ENV_GUARDRAIL_PROVIDER,
    ENV_LAKERA_API_KEY,
    ENV_LAKERA_API_URL,
    ENV_LAKERA_PROJECT_ID,
    GUARDRAIL_PROVIDER_LAKERA,
    LAKERA_DEFAULT_URL,
    lakera_env,
    resolve_guardrail_provider,
)


class GuardrailBlocked(RuntimeError):
    """Raised/handled when the Check Point AI Guardrail flags the user input."""


def blocked_lines(message):
    """One concise line shown when the guardrail blocks a prompt -- a block is a
    security win (rendered green with a ✓ upstream), not an error. `message` is
    the 'Prompt blocked by <engine> (attack detected)...' string."""
    msg = (message or "").strip() or "Prompt blocked by the Check Point AI Guardrail (attack detected)."
    if msg.startswith("GuardrailBlocked: "):
        msg = msg[len("GuardrailBlocked: "):]
    return [f"🛡 {msg}"]


def active_provider(env=None):
    """The selected guardrail provider from CHKP_GUARDRAIL_PROVIDER."""
    e = os.environ if env is None else env
    return resolve_guardrail_provider(e.get(ENV_GUARDRAIL_PROVIDER))


def is_lakera(env=None) -> bool:
    return active_provider(env) == GUARDRAIL_PROVIDER_LAKERA


def _post_json(url, headers, payload, timeout):
    """POST JSON and return the parsed response dict. Uses httpx (a dependency of
    the `mcp` package the tool already requires) whose TLS verification uses
    certifi's CA bundle -- correct on macOS / containers where urllib's default
    SSL context can't find the system root store (raises CERTIFICATE_VERIFY_FAILED).
    Verification stays ON (org policy); a non-2xx status raises (fail-closed).
    Isolated so tests can stub the one network call."""
    import httpx

    resp = httpx.post(url, headers=headers, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def lakera_screen(text, api_key, project_id, url=None, *, timeout=10.0):
    """Screen `text` with the Check Point AI Guardrail (Lakera Guard) API and
    return (flagged, detectors). One POST; `flagged` is the verdict and
    `breakdown` names which detectors fired. Raises on HTTP/auth failure -- a
    broken detector must never silently pass traffic."""
    if not api_key:
        raise ValueError(f"{ENV_LAKERA_API_KEY} is required for the 'lakera' guardrail provider")
    body = _post_json(
        (url or LAKERA_DEFAULT_URL),
        {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        {"messages": [{"role": "user", "content": str(text)}],
         "project_id": project_id, "breakdown": True},
        timeout,
    )
    flagged = bool(body.get("flagged"))
    detectors = [str(item.get("detector_type", "")).split("/")[-1].replace("_", " ")
                 for item in (body.get("breakdown") or []) if item.get("detected")]
    return flagged, detectors


def lakera_creds(env=None, *, cfg=None, session=None):
    """(api_key, project_id, url). Prefer the process env (local runs + .env);
    when the key is absent and a cfg+session are given, hydrate from the
    chkp/lakera-guard Secrets Manager secret (the hosted runtime reads it with
    its execution role). Values are never logged."""
    e = os.environ if env is None else env
    api_key, project_id, url = lakera_env(e)
    if not api_key and cfg is not None and session is not None:
        try:
            sm = session.client("secretsmanager", region_name=cfg.region)
            body = json.loads(sm.get_secret_value(SecretId=cfg.lakera_secret_name())["SecretString"])
            api_key = api_key or body.get(ENV_LAKERA_API_KEY, "")
            project_id = project_id or body.get(ENV_LAKERA_PROJECT_ID) or None
            url = url or body.get(ENV_LAKERA_API_URL) or None
        except Exception:  # noqa: BLE001 -- a SM miss surfaces as the clear "key required" error
            pass
    return api_key, project_id, url


def screen_prompt(text, *, env=None, cfg=None, session=None):
    """Inline Check Point AI Guardrail screen. Returns (flagged, label, detail)."""
    api_key, project_id, url = lakera_creds(env, cfg=cfg, session=session)
    flagged, detectors = lakera_screen(text, api_key, project_id, url)
    return flagged, "Check Point AI Guardrail", (", ".join(detectors) if detectors else "")
