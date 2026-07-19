"""Read-only re-verifier: discover the deployed stack by its fixed names,
mint a fresh Cognito token, and list the aggregated tool catalog through the
gateway. Creates and deletes nothing -- safe to run repeatedly.

Useful right after a deploy: the Cognito hosted domain can take a couple of
minutes to become resolvable, so the deploy's own one-shot check often runs
too early. With --guardrail, verifies the AI guardrail gateway instead (same
Cognito client; separate gateway).
"""

import collections

from . import cognito as cog
from . import mcpcheck
from . import ui
from .awsutil import agentcore_client, log, paginate, resolve_account
from .config import console_links

VERIFY_STEPS = [
    "Discover gateway + targets",
    "Cognito token",
    "Tool catalog through the gateway",
]


def verify(cfg, session, guardrail=False):
    """Read-only re-verify, under the live progress UI. Returns 0 if the
    catalog listed, 1 otherwise."""
    badge = "VERIFY·GUARDRAIL" if guardrail else "VERIFY"
    rep = ui.Reporter("verify", badge, list(VERIFY_STEPS), cfg.region)
    ui.activate(rep)
    try:
        rc, summary = _verify(cfg, session, rep, guardrail)
    except BaseException:
        rep.fail_current()
        ui.deactivate()
        rep.close(ok=False, summary=["Verify aborted -- see the log file."])
        raise
    ui.deactivate()
    rep.close(ok=(rc == 0), summary=summary)
    return rc


def _verify(cfg, session, rep, guardrail):
    region = cfg.region
    rep.begin()  # Discover gateway + targets
    agentcore = agentcore_client(session, region)
    account_id = resolve_account(session, region)
    rep.set_context(f"acct {account_id} · {region}"
                    + ("  ·  guardrail gateway" if guardrail else ""))
    cognito = session.client("cognito-idp", region_name=region)
    cognito_domain = cfg.cognito_domain(account_id)
    gateway_name = cfg.guardrail_gateway_name if guardrail else cfg.gateway_name

    log(f"Account={account_id} Region={region}")

    gateway_id = None
    for gw in paginate(agentcore.list_gateways):
        if gw.get("name") == gateway_name:
            gateway_id = gw.get("gatewayId")
            break
    if not gateway_id:
        hint = ("python3 -m chkpmcpaws guardrail provision" if guardrail
                else "python3 -m chkpmcpaws deploy")
        log(f"No gateway named '{gateway_name}' found.")
        return 1, [f"No gateway '{gateway_name}' found -- is it deployed? Run: {hint}"]
    gw = agentcore.get_gateway(gatewayIdentifier=gateway_id)
    gateway_url = gw.get("gatewayUrl")
    log(f"[gateway] {gateway_name} = {gateway_id}  status={gw.get('status')}")
    log(f"[gateway] url = {gateway_url}")
    engine_cfg = gw.get("policyEngineConfiguration") or {}
    mode = engine_cfg.get("mode") if engine_cfg else None
    if mode:
        log(f"[gateway] policy engine mode = {mode}")

    targets = list(paginate(agentcore.list_gateway_targets, gatewayIdentifier=gateway_id))
    by_status = collections.Counter(t.get("status") for t in targets)
    if targets:
        log(f"[targets] {len(targets)} total -- "
            + ", ".join(f"{k}: {v}" for k, v in sorted(by_status.items())))
        not_ready = [t.get("name") for t in targets if t.get("status") != "READY"]
        if not_ready:
            log(f"[targets] not READY yet: {', '.join(str(n) for n in not_ready)} (re-run shortly)")
    else:
        log("[targets] none found on the gateway.")
    targets_line = (f"{len(targets)} target(s) -- "
                    + ", ".join(f"{k}: {v}" for k, v in sorted(by_status.items()))
                    if targets else "no targets")

    rep.begin()  # Cognito token
    pool_id = cog.find_pool(cognito, cfg.pool_name)
    if not pool_id:
        log(f"No Cognito user pool named '{cfg.pool_name}' found.")
        return 1, [f"No Cognito user pool '{cfg.pool_name}' -- deploy the MCP tools first."]
    client_id = cog.find_client(cognito, pool_id, cfg.app_client_name)
    if not client_id:
        log(f"No Cognito app client named '{cfg.app_client_name}' in pool {pool_id}.")
        return 1, [f"No Cognito app client '{cfg.app_client_name}' in pool {pool_id}."]
    secret = cog.client_secret(cognito, pool_id, client_id)
    log(f"[cognito] pool={pool_id} client_id={client_id} (secret retrieved, not printed)")

    dom = cog.domain_description(cognito, cognito_domain)
    if not dom.get("UserPoolId"):
        log(f"[cognito] hosted domain {cognito_domain} DOES NOT EXIST -- no token can be minted.")
        return 1, [
            f"Hosted domain {cognito_domain} does not exist -- no token can be minted.",
            "Re-run the deploy (python3 -m chkpmcpaws deploy): it waits out a still-deleting",
            "domain from a recent destroy and recreates it, then re-run verify.",
        ]
    owner_note = "" if dom.get("UserPoolId") == pool_id else "  (WARNING: owned by a DIFFERENT pool)"
    log(f"[cognito] hosted domain {cognito_domain} status={dom.get('Status')}{owner_note}")

    endpoint = cog.token_endpoint(cognito_domain, region)
    log(f"[token] {endpoint}")
    access_token = cog.get_token(endpoint, client_id, secret, f"{cfg.res_server}/read")
    if not access_token:
        log("  Could not obtain a Cognito token.")
        return 1, [
            "Could not obtain a Cognito token. If the stack was just built, the hosted",
            "domain may still be propagating -- wait a minute or two and re-run verify.",
        ]
    log("  token acquired.")

    rep.begin()  # Tool catalog
    log("listing the aggregated catalog through the gateway")
    catalog = mcpcheck.verify_tools_mcp(gateway_url, access_token)
    if catalog is None:
        log("  ('mcp' package not installed -- falling back to a stdlib first-page listing.")
        log("   For the full paginated count across all targets:  python3 -m pip install mcp )")
        mcpcheck.list_tools_stdlib_first_page(gateway_url, access_token)

    mem_line = None
    agent_line = None
    if not guardrail:
        from . import memory as mem_mod

        memstate = mem_mod.describe(cfg, session, region)
        if memstate["present"]:
            log(f"[memory] {cfg.memory_name} status={memstate['status']} "
                "(AgentCore Memory -- agent --session)")
            mem_line = f"  Memory  : {cfg.memory_name} · {memstate['status']}"
        else:
            log(f"[memory] {cfg.memory_name} not provisioned "
                "(opt-in; first `agent --session <id>` provisions it)")

        agent_rt = None
        for rt in paginate(agentcore.list_agent_runtimes):
            if rt.get("agentRuntimeName") == cfg.agent_runtime_name:
                agent_rt = rt
                break
        if agent_rt:
            st = agent_rt.get("status")
            log(f"[agent] hosted runtime {cfg.agent_runtime_name} status={st} "
                "(agent --runtime agentcore)")
            agent_line = f"  Agent   : hosted runtime {cfg.agent_runtime_name} · {st}"
        else:
            log(f"[agent] hosted runtime {cfg.agent_runtime_name} not provisioned "
                "(deployed by default; re-run deploy, or any `agent --runtime "
                "agentcore` run builds it)")

    summary = [
        ui.stack_up_banner(ok=True) + f"  ·  {'guardrail' if guardrail else 'MCP tools'} · {region}",
        f"  Gateway : {gateway_url}",
        f"  Status  : {gw.get('status')}   ·   {targets_line}",
    ]
    if mode:
        summary.append(f"  Policy engine mode : {mode}")
    if mem_line:
        summary.append(mem_line)
    if agent_line:
        summary.append(agent_line)
    if catalog:
        summary += [""] + catalog
    elif catalog is None:
        summary.append("  (install the 'mcp' package for the full paginated tool count)")
    summary += ui.links_block(console_links(cfg, account_id, gateway_id=gateway_id,
                                            pool_id=pool_id,
                                            include_agent=not guardrail),
                              title="Open in the AWS Console:")
    return 0, summary
