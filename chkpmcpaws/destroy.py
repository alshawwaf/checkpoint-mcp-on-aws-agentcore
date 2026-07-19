"""MCP tools teardown, in dependency order:

  targets -> gateway -> runtimes -> Cognito -> CodeBuild -> ECR -> S3 -> IAM -> secret

Idempotent: every step tolerates an already-absent resource, so a partial
build can still be fully cleaned up. Removes ONLY resources with this stack's
names (see chkpmcpaws.config); production networking added outside these tools
(NAT, EIPs, VPCs, extra secrets) is never touched.

The secret may hold REAL Check Point credentials by go-live, so by default it
is scheduled for deletion with a 7-day recovery window; the deploy restores a
scheduled-for-deletion secret automatically, so a rebuild inside the window
still works. force_delete_secret=True purges immediately (old behavior).
"""

from . import cognito as cog
from .awsutil import (
    BotoCoreError,
    ClientError,
    agentcore_client,
    delete_role,
    log,
    paginate,
    resolve_account,
    swallow,
    wait_until,
)


def inventory(cfg, session, agentcore, account_id):
    """Read-only probe of what an MCP tools teardown would actually remove.
    Returns human-readable findings (empty list = nothing of this stack's
    exists). Lets the CLI show an honest confirmation prompt and skip work
    on a clean account."""
    region = cfg.region
    found = []
    if any(gw.get("name") == cfg.gateway_name for gw in paginate(agentcore.list_gateways)):
        found.append(f"gateway {cfg.gateway_name} (+ its targets)")
    n_runtimes = sum(
        1
        for rt in paginate(agentcore.list_agent_runtimes)
        if str(rt.get("agentRuntimeName", "")).startswith(cfg.runtime_scan_prefix)
    )
    if n_runtimes:
        found.append(f"{n_runtimes} runtime(s) named {cfg.runtime_scan_prefix}*")
    cognito = session.client("cognito-idp", region_name=region)
    pools = [
        p
        for p in paginate(cognito.list_user_pools, MaxResults=60)
        if p.get("Name") == cfg.pool_name
    ]
    if pools:
        dup = f" ({len(pools)} duplicates)" if len(pools) > 1 else ""
        found.append(f"Cognito pool {cfg.pool_name}{dup} (+ domain/client)")
    codebuild = session.client("codebuild", region_name=region)
    try:
        if codebuild.batch_get_projects(names=[cfg.cb_project]).get("projects"):
            found.append(f"CodeBuild project {cfg.cb_project}")
    except (ClientError, BotoCoreError):
        pass
    ecr = session.client("ecr", region_name=region)
    try:
        ecr.describe_repositories(repositoryNames=[cfg.ecr_repo])
        found.append(f"ECR repository {cfg.ecr_repo}")
    except (ClientError, BotoCoreError):
        pass
    s3 = session.client("s3", region_name=region)
    try:
        s3.head_bucket(Bucket=cfg.src_bucket(account_id))
        found.append(f"S3 bucket {cfg.src_bucket(account_id)}")
    except (ClientError, BotoCoreError):
        pass
    iam = session.client("iam", region_name=region)
    roles = []
    for role in (cfg.rt_role, cfg.gw_role, cfg.cb_role):
        try:
            iam.get_role(RoleName=role)
            roles.append(role)
        except (ClientError, BotoCoreError):
            pass
    if roles:
        found.append("IAM role(s): " + ", ".join(roles))
    secretsmanager = session.client("secretsmanager", region_name=region)
    live = []
    for name in cfg.all_secret_names():
        try:
            desc = secretsmanager.describe_secret(SecretId=name)
            if not desc.get("DeletedDate"):  # scheduled-for-deletion = already handled
                live.append(name)
        except (ClientError, BotoCoreError):
            pass
    if live:
        found.append(f"{len(live)} secret(s): " + ", ".join(live))
    from . import memory as mem_mod

    memstate = mem_mod.describe(cfg, session, region)
    if memstate["present"]:
        found.append(f"AgentCore Memory {cfg.memory_name} ({memstate['status']})")
    try:
        iam.get_role(RoleName=cfg.memory_role)
        found.append(f"IAM role: {cfg.memory_role} (memory)")
    except (ClientError, BotoCoreError):
        pass
    try:
        ecr.describe_repositories(repositoryNames=[cfg.agent_ecr_repo])
        found.append(f"hosted-agent ECR repository {cfg.agent_ecr_repo}")
    except (ClientError, BotoCoreError):
        pass
    from . import bridge as bridge_mod

    if bridge_mod.describe(cfg, session)["present"]:
        found.append(f"HTTPS bridge {cfg.bridge_fn} (+ role, token secret)")
    ssm = session.client("ssm", region_name=region)
    try:
        import json as _json
        enabled = _json.loads(ssm.get_parameter(Name=cfg.model_access_param)["Parameter"]["Value"])
        if enabled:
            found.append(f"{len(enabled)} Bedrock model agreement(s) this stack enabled "
                         "(will be revoked)")
    except (ClientError, BotoCoreError, ValueError, KeyError):
        pass
    return found


def destroy_mcp_tools(cfg, session, force_delete_secret=False):
    """Remove the MCP tools stack. Returns 0 (best-effort, idempotent)."""
    region = cfg.region
    agentcore = agentcore_client(session, region)
    account_id = resolve_account(session, region)

    src_bucket = cfg.src_bucket(account_id)
    cognito_domain = cfg.cognito_domain(account_id)

    secretsmanager = session.client("secretsmanager", region_name=region)
    iam = session.client("iam", region_name=region)
    ecr = session.client("ecr", region_name=region)
    s3 = session.client("s3", region_name=region)
    codebuild = session.client("codebuild", region_name=region)
    cognito = session.client("cognito-idp", region_name=region)

    log("==============================================================")
    log(f" Teardown (MCP tools)  account={account_id}  region={region}")
    log("==============================================================")

    # ---------------------------------------------------------------------
    # 1) Gateway TARGET(s) -> Gateway (targets must be deleted first)
    # ---------------------------------------------------------------------
    gateway_id = None
    for gw in paginate(agentcore.list_gateways):
        if gw.get("name") == cfg.gateway_name:
            gateway_id = gw.get("gatewayId")
            break

    if gateway_id:
        log(f"[gateway] {cfg.gateway_name} = {gateway_id}")
        for t in paginate(agentcore.list_gateway_targets, gatewayIdentifier=gateway_id):
            tid = t.get("targetId")
            log(f"  [target] deleting {tid}")
            swallow(
                agentcore.delete_gateway_target,
                gatewayIdentifier=gateway_id,
                targetId=tid,
            )
        wait_until(
            lambda: not list(
                paginate(agentcore.list_gateway_targets, gatewayIdentifier=gateway_id)
            ),
            attempts=30,
            delay=5,
            label="gateway targets deleted",
        )
        log(f"  [gateway] deleting {gateway_id}")
        swallow(agentcore.delete_gateway, gatewayIdentifier=gateway_id)
        wait_until(
            lambda: not any(
                gw.get("gatewayId") == gateway_id
                for gw in paginate(agentcore.list_gateways)
            ),
            attempts=30,
            delay=5,
            label="gateway deleted",
        )
    else:
        log(f"[gateway] {cfg.gateway_name} not found -- skipping gateway + targets.")

    # ---------------------------------------------------------------------
    # 2) AgentCore RUNTIME(s) -- every runtime this stack's names own
    # ---------------------------------------------------------------------
    scan = cfg.runtime_scan_prefix

    def _stack_runtimes():
        return [
            rt
            for rt in paginate(agentcore.list_agent_runtimes)
            if str(rt.get("agentRuntimeName", "")).startswith(scan)
        ]

    found = _stack_runtimes()
    if found:
        for rt in found:
            rid = rt.get("agentRuntimeId")
            log(f"[runtime] deleting {rid} ({rt.get('agentRuntimeName')})")
            swallow(agentcore.delete_agent_runtime, agentRuntimeId=rid)
        if not wait_until(
            lambda: not _stack_runtimes(), attempts=40, delay=5, label="runtimes deleted"
        ):
            log("  [runtime] verify manually with:")
            log(f"    aws bedrock-agentcore-control list-agent-runtimes --region {region}")
    else:
        log(f"[runtime] no {scan}* runtimes found -- skipping.")

    # ---------------------------------------------------------------------
    # 3) COGNITO (app clients -> hosted domain -> user pool). Delete EVERY
    #    pool with the fixed name: a pre-fix deploy minted a duplicate pool
    #    per re-run, so there may be more than one to clean up.
    # ---------------------------------------------------------------------
    pool_ids = [
        p.get("Id")
        for p in paginate(cognito.list_user_pools, MaxResults=60)
        if p.get("Name") == cfg.pool_name
    ]
    if pool_ids:
        if len(pool_ids) > 1:
            log(f"[cognito] {len(pool_ids)} pools named {cfg.pool_name} found "
                "(duplicates from earlier re-runs) -- deleting all of them")
        for pool_id in pool_ids:
            log(f"[cognito] user pool {cfg.pool_name} = {pool_id}")
            for c in paginate(
                cognito.list_user_pool_clients, UserPoolId=pool_id, MaxResults=60
            ):
                cid = c.get("ClientId")
                log(f"  [cognito] deleting app client {cid}")
                swallow(
                    cognito.delete_user_pool_client, UserPoolId=pool_id, ClientId=cid
                )
            # Only one pool owns the hosted domain; the others just skip.
            log(f"  [cognito] deleting hosted domain {cognito_domain}")
            swallow(
                cognito.delete_user_pool_domain,
                Domain=cognito_domain,
                UserPoolId=pool_id,
            )
            # Domain deletion is ASYNC. If we return while it is still
            # draining, an immediate redeploy cannot recreate the same-named
            # domain and ends up with no token endpoint -- wait it out here.
            if cog.domain_description(cognito, cognito_domain).get("UserPoolId") == pool_id:
                log("  [cognito] waiting for the hosted domain deletion to finish "
                    "(async; protects an immediate redeploy)...")
                wait_until(
                    lambda: cog.domain_description(cognito, cognito_domain).get("UserPoolId")
                    != pool_id,
                    attempts=36,
                    delay=5,
                    label=f"hosted domain {cognito_domain} deleted",
                )
            log(f"  [cognito] deleting user pool {pool_id}")
            swallow(cognito.delete_user_pool, UserPoolId=pool_id)
    else:
        log(f"[cognito] user pool {cfg.pool_name} not found -- skipping.")

    # ---------------------------------------------------------------------
    # 4) CODEBUILD project, 5) ECR repository, 6) S3 source bucket
    # ---------------------------------------------------------------------
    log(f"[codebuild] deleting project {cfg.cb_project}")
    swallow(codebuild.delete_project, name=cfg.cb_project)

    log(f"[ecr] deleting repository {cfg.ecr_repo}")
    swallow(ecr.delete_repository, repositoryName=cfg.ecr_repo, force=True)

    try:
        s3.head_bucket(Bucket=src_bucket)
        bucket_exists = True
    except ClientError:
        bucket_exists = False
    if bucket_exists:
        log(f"[s3] emptying and deleting s3://{src_bucket}")
        try:
            token = None
            while True:
                kw = {"Bucket": src_bucket}
                if token:
                    kw["ContinuationToken"] = token
                resp = s3.list_objects_v2(**kw)
                objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
                if objs:
                    s3.delete_objects(Bucket=src_bucket, Delete={"Objects": objs})
                if not resp.get("IsTruncated"):
                    break
                token = resp.get("NextContinuationToken")
        except ClientError:
            pass
        swallow(s3.delete_bucket, Bucket=src_bucket)
    else:
        log(f"[s3] bucket {src_bucket} not found -- skipping.")

    # ---------------------------------------------------------------------
    # 7) IAM roles (inline + managed handled), 8) secret
    # ---------------------------------------------------------------------
    for role in (cfg.rt_role, cfg.gw_role, cfg.cb_role):
        delete_role(iam, role)

    # Every per-group secret this stack could have created. We don't know which
    # servers were deployed, so consider them all -- but only act on the ones
    # that actually exist, to keep the output honest.
    deleted_any = False
    for name in cfg.all_secret_names():
        try:
            secretsmanager.describe_secret(SecretId=name)
        except (ClientError, BotoCoreError):
            continue  # not present -- nothing to delete
        deleted_any = True
        if force_delete_secret:
            log(f"[secret] force-deleting {name} (no recovery window)")
            swallow(secretsmanager.delete_secret, SecretId=name,
                    ForceDeleteWithoutRecovery=True)
        else:
            log(f"[secret] scheduling {name} for deletion (7-day recovery window)")
            swallow(secretsmanager.delete_secret, SecretId=name, RecoveryWindowInDays=7)
    if deleted_any and not force_delete_secret:
        log("  (secrets recoverable for 7 days; a rebuild restores them automatically.")
        log("   Use --force-delete-secret to purge immediately.)")

    # ---------------------------------------------------------------------
    # 9) AgentCore Memory + its execution role (only present if the agent was
    #    ever run with --session). Idempotent -- no-op when absent.
    # ---------------------------------------------------------------------
    from . import memory as mem_mod

    removed = mem_mod.delete_memory(cfg, session, region)
    if removed:
        log(f"[memory] deleted {removed}")
    else:
        log(f"[memory] {cfg.memory_name} not found -- skipping.")

    # ---------------------------------------------------------------------
    # 10) HTTPS bridge (only present if `bridge provision` was run).
    # ---------------------------------------------------------------------
    from . import bridge as bridge_mod

    bridge_mod.destroy(cfg, session)

    # ---------------------------------------------------------------------
    # 11) Bedrock model access -- revoke ONLY the Claude agreements THIS stack
    #     enabled (tracked in an SSM marker); pre-existing access is untouched.
    # ---------------------------------------------------------------------
    from . import models as models_mod

    revoked = models_mod.disable_enabled(cfg, session)
    if revoked:
        log(f"[models] {revoked}")
    else:
        log("[models] no model access enabled by this stack -- skipping.")

    # ---------------------------------------------------------------------
    # 10) Hosted-agent leftovers (--runtime agentcore): its ECR repo, exec role
    #     and -agent CodeBuild project. The chkp_agent RUNTIME itself is caught
    #     by the chkp_* runtime scan above.
    # ---------------------------------------------------------------------
    from . import hosting

    host_removed = hosting.destroy_extras(cfg, session)
    if host_removed:
        log(f"[hosted-agent] deleted {host_removed}")
    else:
        log("[hosted-agent] no hosted-agent extras found -- skipping.")

    log("==============================================================")
    log(" MCP tools teardown complete.")
    log("==============================================================")
    return 0
