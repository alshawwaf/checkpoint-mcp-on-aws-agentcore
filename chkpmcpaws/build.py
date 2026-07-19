"""MCP tools deploy: Check Point MCP servers as tools behind one AgentCore Gateway.

Port of the field-tested scripts/build.py flow onto the shared package
helpers. The step order, API calls, and resource semantics are unchanged:

  [1] placeholder secret        [6] Cognito pool + M2M client (find-before-create)
  [2] runtime execution role    [7] gateway service role
  [3] generic container source  [8] gateway (CUSTOM_JWT; authorizer self-heal on reuse)
  [4] CodeBuild ARM64 image     [9] one gateway target per runtime
  [5] one runtime per server   [10] hosted agent runtime (skip with --no-agent)
                               [11] Cognito token + tools/list verification

Writes ONLY a placeholder Check Point credential. Real credentials go into
Secrets Manager separately at go-live (docs/scenarios/go-live-and-operations.md).
"""

import json
import os
import tempfile
import time
import urllib.parse
import zipfile

from . import config
from . import cognito as cog
from . import mcpcheck
from . import ui
from .awsutil import (
    BotoCoreError,
    ClientError,
    agentcore_client,
    err_code,
    log,
    paginate,
    poll,
    resolve_account,
    supports_param,
)

DEPLOY_STEPS = [
    "Preflight — identity + clients",
    "Claude model access",
    "Placeholder secret",
    "Runtime execution role",
    "Container source (entrypoint + Dockerfile)",
    "CodeBuild ARM64 image",
    "AgentCore runtimes",
    "Cognito pool + M2M client",
    "Gateway service role",
    "Gateway (MCP · Custom-JWT)",
    "Gateway targets",
    "Hosted agent runtime",
    "Token + tools/list verify",
]

# Literal container files (no interpolation). buildspec.yml IS interpolated below.
ENTRYPOINT_MJS = r"""import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { spawn } from "node:child_process";
const region = process.env.AWS_REGION || "us-east-1";
const secretId = process.env.CHKP_SECRET_ARN;
if (secretId) {
  const sm = new SecretsManagerClient({ region });
  const res = await sm.send(new GetSecretValueCommand({ SecretId: secretId }));
  for (const [k, v] of Object.entries(JSON.parse(res.SecretString))) process.env[k] = String(v);
}
const pkg = process.env.CHKP_PKG || "@chkp/quantum-management-mcp";   // set PER runtime
// Optional per-server startup flags (e.g. documentation-mcp needs --region).
const extra = (process.env.CHKP_ARGS || "").split(" ").filter(Boolean);
const child = spawn("npx", ["-y", pkg, "--transport", "http", "--transport-port", "8000", ...extra], { stdio: "inherit", env: process.env });
child.on("exit", (c) => process.exit(c ?? 0));
"""

# Base image is pulled from AWS's public ECR mirror of Docker Hub official
# images, NOT docker.io directly: CodeBuild egresses from shared NAT IPs that
# routinely hit Docker Hub's anonymous pull rate limit (HTTP 429), which fails
# the build. The mirror needs no credentials and isn't subject to that limit.
DOCKERFILE = r"""FROM --platform=linux/arm64 public.ecr.aws/docker/library/node:20-slim
ENV MCP_TRANSPORT_TYPE=http MCP_TRANSPORT_PORT=8000 TELEMETRY_DISABLED=true
WORKDIR /app
# npx fetches the specific @chkp package at runtime from $CHKP_PKG -> ONE image serves every server
RUN npm install @aws-sdk/client-secrets-manager
COPY entrypoint.mjs /app/entrypoint.mjs
EXPOSE 8000
ENTRYPOINT ["node","/app/entrypoint.mjs"]
"""

# The ONLY credentials this module writes anywhere are non-real PLACEHOLDERs
# (chkpmcpaws.config.CRED_SHAPE), one per-server secret for each selected server
# that needs creds. Never a real secret -- real creds go in via `chkpmcpaws creds`.


def deploy(cfg, session, creds_file=None, include_agent=True, enable_models=True):
    """Provision the MCP tools stack. Returns 0, or 1 on partial failure --
    the exit code must never report a partial deploy as success.

    creds_file: optional local .env/.json; when given, each server's REAL
    credentials from that file are written as its secret at deploy time (so the
    runtime boots with them -- no separate `creds apply`). Servers absent from
    the file get placeholders. Values are never logged.

    include_agent: also provision the hosted agent runtime (chkp_agent) so
    `agent --runtime agentcore` is instant from the first ask. Skip with
    deploy --no-agent for a lighter stack.

    enable_models: grant Bedrock access to the preferred Claude models (recorded
    so destroy revokes only what we enabled). Skip with deploy --no-model-access."""
    steps = list(DEPLOY_STEPS)
    if not include_agent:
        steps.remove("Hosted agent runtime")
    if not enable_models:
        steps.remove("Claude model access")
    rep = ui.Reporter("deploy", "DEPLOY", steps, cfg.region)
    ui.activate(rep)
    try:
        rc, ok, summary = _deploy(cfg, session, rep, creds_file, include_agent, enable_models)
    except BaseException:
        rep.fail_current()
        ui.deactivate()
        rep.close(ok=False, summary=["Deploy aborted -- details above and in the log file."])
        raise
    ui.deactivate()
    rep.close(ok=ok, summary=summary)
    return rc


def _has_placeholder(body):
    """True if any value is an unedited placeholder."""
    return any(str(v).startswith("PLACEHOLDER") or str(v).startswith("replace-with")
               for v in body.values())


def _load_creds_overrides(creds_file):
    """Parse the optional --creds file into {server: {KEY: value}}; tolerant of
    a missing/unparseable file (falls back to placeholders with a note)."""
    if not creds_file:
        return {}
    if not os.path.exists(creds_file):
        log(f"  --creds {creds_file} not found; writing placeholders to fill in later")
        return {}
    try:
        from . import creds  # local import avoids a module-level cycle
        return creds.load_file(creds_file)
    except (OSError, ValueError) as e:
        log(f"  could not read --creds {creds_file}: {e}; writing placeholders")
        return {}


def _deploy(cfg, session, rep, creds_file=None, include_agent=True, enable_models=True):
    region = cfg.region
    rep.begin()  # Preflight
    agentcore = agentcore_client(session, region)
    account_id = resolve_account(session, region)
    rep.set_context(f"acct {account_id} · {region} · {len(cfg.servers)} servers")

    # Claude model access -- grant it up front so the agent gets its preferred
    # model, and the user never clicks through the Bedrock console. Non-fatal:
    # a deploy still works on Nova if this can't complete.
    if enable_models:
        rep.begin("Claude model access")
        from . import models as models_mod
        try:
            models_mod.enable(cfg, session)
        except Exception as e:  # noqa: BLE001 -- never fail a deploy on model access
            log(f"  model access step errored ({type(e).__name__}: {str(e)[:120]}) "
                "-- continuing; the agent falls back to Nova.")

    src_bucket = cfg.src_bucket(account_id)
    cognito_domain = cfg.cognito_domain(account_id)
    image_uri = cfg.image_uri(account_id)

    log(f"Account={account_id} Region={region}")
    log(f"Servers: {' '.join(cfg.servers)}")

    secretsmanager = session.client("secretsmanager", region_name=region)
    iam = session.client("iam", region_name=region)
    ecr = session.client("ecr", region_name=region)
    s3 = session.client("s3", region_name=region)
    codebuild = session.client("codebuild", region_name=region)
    cognito = session.client("cognito-idp", region_name=region)

    # Steps that fail but shouldn't abort the whole build are recorded here.
    failures = []

    # ---------------------------------------------------------------------
    # 1. Placeholder secret PER SERVER that needs credentials. Every server
    #    gets its OWN chkp/<server> secret, and its runtime points
    #    CHKP_SECRET_ARN at it -- so two servers can use different Check Point
    #    credentials. Real creds come later via `chkpmcpaws creds`.
    # ---------------------------------------------------------------------
    cred_servers = cfg.servers_with_creds(cfg.servers)
    overrides = _load_creds_overrides(creds_file)
    rep.begin(f"Secrets ({len(cred_servers)} server(s))")
    server_arn = {}
    n_real = 0
    for s in cred_servers:
        name = cfg.secret_name(s)
        real = overrides.get(s)
        is_real = bool(real) and isinstance(real, dict) and not _has_placeholder(real)
        body = json.dumps(real if is_real else cfg.placeholder_for(s))
        if is_real:
            n_real += 1
        log(f"  {s} -> {name}" + ("  (real creds from --creds)" if is_real else ""))
        try:
            secretsmanager.create_secret(Name=name, SecretString=body, Tags=cfg.tags_kv())
        except ClientError as e:
            if err_code(e) == "ResourceExistsException":
                # Update to the file's value if real creds were given; otherwise
                # leave any existing value untouched (don't clobber real creds).
                if is_real:
                    secretsmanager.put_secret_value(SecretId=name, SecretString=body)
            elif err_code(e) == "InvalidRequestException" and "deletion" in str(e).lower():
                log(f"    {name} scheduled for deletion; restoring it")
                secretsmanager.restore_secret(SecretId=name)
                secretsmanager.put_secret_value(SecretId=name, SecretString=body)
            else:
                raise
        arn = secretsmanager.describe_secret(SecretId=name)["ARN"]
        # Only SERVER-side secrets are wired into the container (CHKP_SECRET_ARN).
        # Agent-side secrets (quantum-gaia) are created here but read by the
        # agent, NOT injected into the server container.
        if cfg.server_needs_creds(s):
            server_arn[s] = arn
    if creds_file:
        log(f"  {n_real}/{len(cred_servers)} secret(s) set from --creds; the rest are placeholders")
    log("  secret(s) written (values not printed)")

    # ---------------------------------------------------------------------
    # 2. Runtime execution role (Workload resource wildcarded across servers)
    # ---------------------------------------------------------------------
    rep.begin(f"Runtime execution role ({cfg.rt_role})")
    rt_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AssumeRolePolicy",
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:bedrock-agentcore:{region}:{account_id}:*"
                    },
                },
            }
        ],
    }
    rt_exec = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ECRPull",
                "Effect": "Allow",
                "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
                "Resource": f"arn:aws:ecr:{region}:{account_id}:repository/{cfg.ecr_repo}",
            },
            {
                "Sid": "ECRAuth",
                "Effect": "Allow",
                "Action": "ecr:GetAuthorizationToken",
                "Resource": "*",
            },
            {
                "Sid": "Logs",
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "logs:DescribeLogStreams",
                    "logs:DescribeLogGroups",
                ],
                "Resource": "*",
            },
            {
                "Sid": "Metrics",
                "Effect": "Allow",
                "Action": "cloudwatch:PutMetricData",
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"cloudwatch:namespace": "bedrock-agentcore"}
                },
            },
            {
                "Sid": "Workload",
                "Effect": "Allow",
                "Action": [
                    "bedrock-agentcore:GetWorkloadAccessToken",
                    "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
                    "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
                ],
                "Resource": [
                    f"arn:aws:bedrock-agentcore:{region}:{account_id}:workload-identity-directory/default",
                    f"arn:aws:bedrock-agentcore:{region}:{account_id}:workload-identity-directory/default/workload-identity/*",
                ],
            },
            {
                "Sid": "Secrets",
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                # All of this stack's per-server secrets (chkp/quantum-management,
                # chkp/cloudguard-waf, ...). The random ARN suffix is covered
                # by the trailing wildcard.
                "Resource": f"arn:aws:secretsmanager:{region}:{account_id}:secret:chkp/*",
            },
        ],
    }
    _ensure_role(iam, cfg.rt_role, rt_trust, cfg)
    iam.put_role_policy(
        RoleName=cfg.rt_role,
        PolicyName="AgentCoreRuntimeExec",
        PolicyDocument=json.dumps(rt_exec),
    )
    rt_role_arn = f"arn:aws:iam::{account_id}:role/{cfg.rt_role}"

    # ---------------------------------------------------------------------
    # 3. Generic container source + 4. Build the ARM64 image on CodeBuild
    # ---------------------------------------------------------------------
    rep.begin("Container source (entrypoint.mjs + Dockerfile)")
    buildspec = (
        "version: 0.2\n"
        "phases:\n"
        '  pre_build: {commands: ["aws ecr get-login-password --region '
        + region
        + " | docker login --username AWS --password-stdin "
        + f"{account_id}.dkr.ecr.{region}.amazonaws.com" + '"]}\n'
        '  build: {commands: ["docker build -t '
        + image_uri
        + ' .","docker push '
        + image_uri
        + '"]}\n'
    )

    src_dir = tempfile.mkdtemp(prefix="chkp-mcp-")
    for fname, content in (
        ("entrypoint.mjs", ENTRYPOINT_MJS),
        ("Dockerfile", DOCKERFILE),
        ("buildspec.yml", buildspec),
    ):
        with open(os.path.join(src_dir, fname), "w", newline="\n") as fh:
            fh.write(content)
    # Zip the three files at the archive ROOT (CodeBuild expects buildspec.yml
    # at the top level of the S3 source).
    zip_path = os.path.join(src_dir, "src.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname in ("entrypoint.mjs", "Dockerfile", "buildspec.yml"):
            zf.write(os.path.join(src_dir, fname), arcname=fname)

    rep.begin("CodeBuild ARM64 image (server-side; no local Docker)")
    try:
        ecr.create_repository(repositoryName=cfg.ecr_repo, tags=cfg.tags_kv())
    except ClientError as e:
        if err_code(e) != "RepositoryAlreadyExistsException":
            raise

    cb_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codebuild.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    _ensure_role(iam, cfg.cb_role, cb_trust, cfg)
    # Scoped inline policy: exactly what this build needs (login + push to the
    # one ECR repo, logs for the one project, read the one source object).
    cb_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EcrAuth",
                "Effect": "Allow",
                "Action": "ecr:GetAuthorizationToken",
                "Resource": "*",
            },
            {
                "Sid": "EcrPushPull",
                "Effect": "Allow",
                "Action": [
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:CompleteLayerUpload",
                    "ecr:InitiateLayerUpload",
                    "ecr:PutImage",
                    "ecr:UploadLayerPart",
                    "ecr:BatchGetImage",
                    "ecr:GetDownloadUrlForLayer",
                ],
                "Resource": f"arn:aws:ecr:{region}:{account_id}:repository/{cfg.ecr_repo}",
            },
            {
                "Sid": "Logs",
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                "Resource": f"arn:aws:logs:{region}:{account_id}:log-group:/aws/codebuild/{cfg.cb_project}*",
            },
            {
                "Sid": "SrcObject",
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion"],
                "Resource": f"arn:aws:s3:::{src_bucket}/src.zip",
            },
            {
                "Sid": "SrcBucket",
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                "Resource": f"arn:aws:s3:::{src_bucket}",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=cfg.cb_role,
        PolicyName="ChkpMcpCodeBuildScoped",
        PolicyDocument=json.dumps(cb_policy),
    )
    # Migration: earlier builds attached broad managed policies to this role;
    # detach them so re-used roles converge on the scoped policy above.
    for p in (
        "AmazonEC2ContainerRegistryPowerUser",
        "CloudWatchLogsFullAccess",
        "AmazonS3ReadOnlyAccess",
    ):
        try:
            iam.detach_role_policy(
                RoleName=cfg.cb_role, PolicyArn=f"arn:aws:iam::aws:policy/{p}"
            )
        except ClientError:
            pass  # not attached (fresh role) -- nothing to migrate
    cb_role_arn = f"arn:aws:iam::{account_id}:role/{cfg.cb_role}"

    # S3 source bucket (us-east-1 = no LocationConstraint).
    try:
        if region == "us-east-1":
            s3.create_bucket(Bucket=src_bucket)
        else:
            s3.create_bucket(
                Bucket=src_bucket,
                CreateBucketConfiguration={"LocationConstraint": region},
            )
    except ClientError as e:
        if err_code(e) not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise
    try:
        s3.put_bucket_tagging(
            Bucket=src_bucket, Tagging={"TagSet": cfg.tags_kv()}
        )
    except ClientError:
        pass  # tagging is best-effort
    s3.upload_file(zip_path, src_bucket, "src.zip")

    log("  Sleeping 15s for CodeBuild role propagation...")
    time.sleep(15)

    try:
        codebuild.create_project(
            name=cfg.cb_project,
            source={"type": "S3", "location": f"{src_bucket}/src.zip"},
            artifacts={"type": "NO_ARTIFACTS"},
            environment={
                "type": "ARM_CONTAINER",
                "image": "aws/codebuild/amazonlinux2-aarch64-standard:3.0",
                # SMALL is plenty for a two-layer node:20-slim image.
                "computeType": "BUILD_GENERAL1_SMALL",
                "privilegedMode": True,
            },
            serviceRole=cb_role_arn,
            tags=cfg.tags_kv(key="key", value="value"),
        )
    except ClientError as e:
        if err_code(e) != "ResourceAlreadyExistsException":
            raise

    build_id = codebuild.start_build(projectName=cfg.cb_project)["build"]["id"]
    log(f"  CodeBuild {build_id} -- waiting for SUCCEEDED...")
    while True:
        try:
            status = codebuild.batch_get_builds(ids=[build_id])["builds"][0][
                "buildStatus"
            ]
        except (ClientError, IndexError, KeyError):
            status = "IN_PROGRESS"
        log(f"    {status}")
        if status == "SUCCEEDED":
            break
        if status in ("FAILED", "FAULT", "STOPPED", "TIMED_OUT"):
            log("build failed -- inspect the CodeBuild logs for project "
                f"{cfg.cb_project} in the console.")
            rep.fail_current()
            return 1, False, [
                f"✗ DEPLOY STOPPED -- the CodeBuild image build ended {status}.",
                f"  Inspect the CodeBuild logs for project {cfg.cb_project}, fix, and",
                "  re-run the deploy (idempotent -- it resumes where it stopped).",
            ]
        time.sleep(15)

    # ---------------------------------------------------------------------
    # 5. One AgentCore Runtime per server (collect ARNs/IDs)
    # ---------------------------------------------------------------------
    rep.begin(f"AgentCore runtimes ({len(cfg.servers)} servers)")
    runtime_tags_ok = supports_param(agentcore, "CreateAgentRuntime", "tags")
    runtimes = []  # list of dicts: {server, arn, id}
    for s in cfg.servers:
        aname = cfg.runtime_name(s)
        env = {"CHKP_PKG": cfg.pkg_spec(s), "AWS_REGION": region}
        # quantum-gaia's secret is agent-side (not wired here); every
        # server-credentialed server points CHKP_SECRET_ARN at its OWN secret.
        if s in server_arn:
            env["CHKP_SECRET_ARN"] = server_arn[s]
        # Some packages need extra startup flags (e.g. documentation --region).
        extra_args = cfg.startup_args(s)
        if extra_args:
            env["CHKP_ARGS"] = extra_args
        log(f"  -- runtime for @chkp/{s}-mcp  (name: {aname}, "
            f"creds: {'own secret' if s in server_arn else 'none'})")
        kwargs = dict(
            agentRuntimeName=aname,
            agentRuntimeArtifact={
                "containerConfiguration": {"containerUri": image_uri}
            },
            roleArn=rt_role_arn,
            networkConfiguration={"networkMode": "PUBLIC"},
            protocolConfiguration={"serverProtocol": "MCP"},
            environmentVariables=env,
        )
        if runtime_tags_ok:
            kwargs["tags"] = cfg.tags()
        try:
            resp = agentcore.create_agent_runtime(**kwargs)
            runtimes.append(
                {"server": s, "arn": resp["agentRuntimeArn"], "id": resp["agentRuntimeId"]}
            )
        except ClientError as e:
            # Idempotent re-run: already exists -> look it up by name.
            existing = _find_runtime_by_name(agentcore, aname)
            if existing:
                log(f"     already exists; reusing {existing['id']}")
                runtimes.append(
                    {"server": s, "arn": existing["arn"], "id": existing["id"]}
                )
            else:
                log(f"     create failed for {s}: {err_code(e)} {e}")
                failures.append(f"runtime create {s}: {err_code(e) or e}")
                rep.warn_current()
                continue

    log("  Waiting for runtimes to reach READY...")
    ready_runtimes = []
    for rt in runtimes:
        rid = rt["id"]
        ok = poll(
            lambda rid=rid: agentcore.get_agent_runtime(agentRuntimeId=rid).get("status"),
            "READY",
            {"CREATE_FAILED", "UPDATE_FAILED"},
            attempts=80,
            delay=10,
            label=f"runtime {rt['server']}",
        )
        if ok:
            ready_runtimes.append(rt)
        else:
            # poll() announced why. Distinguish hard-failed from still-creating:
            try:
                st = agentcore.get_agent_runtime(agentRuntimeId=rid).get("status")
            except ClientError:
                st = None
            if st in ("CREATE_FAILED", "UPDATE_FAILED"):
                log(f"  runtime {rt['server']} ({rid}) is {st} -- excluded from gateway targets.")
                failures.append(f"runtime {rt['server']}: {st}")
                rep.warn_current()
            else:
                log(f"  WARNING: runtime {rt['server']} not READY yet; its target may not sync until it is.")
                ready_runtimes.append(rt)
    runtimes = ready_runtimes

    # ---------------------------------------------------------------------
    # 6. Cognito user pool + M2M client (find-before-create; see chkpmcpaws.cognito)
    # ---------------------------------------------------------------------
    rep.begin("Cognito pool + M2M client")
    pool_id = cog.ensure_pool(cognito, cfg.pool_name, tags=cfg.tags())
    cog.ensure_resource_server(
        cognito,
        pool_id,
        cfg.res_server,
        "GatewayResourceServer",
        [{"ScopeName": "read", "ScopeDescription": "Read access"}],
    )
    client_id, client_secret = cog.ensure_client(
        cognito, pool_id, cfg.app_client_name, f"{cfg.res_server}/read"
    )
    if not cog.ensure_domain(cognito, cognito_domain, pool_id):
        failures.append(
            f"cognito hosted domain {cognito_domain}: not attached -- token minting will fail"
        )
        rep.warn_current()

    discovery_url = cog.discovery_url(region, pool_id)
    token_endpoint = cog.token_endpoint(cognito_domain, region)
    log(f"  pool={pool_id} client_id={client_id}")

    # ---------------------------------------------------------------------
    # 7. Gateway service role (InvokeAgentRuntime on every runtime)
    # ---------------------------------------------------------------------
    rep.begin(f"Gateway service role ({cfg.gw_role})")
    gw_trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "GatewayAssumeRolePolicy",
                "Effect": "Allow",
                "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    _ensure_role(iam, cfg.gw_role, gw_trust, cfg)
    gw_invoke = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "InvokeRuntimeTargets",
                "Effect": "Allow",
                "Action": "bedrock-agentcore:InvokeAgentRuntime",
                "Resource": [
                    f"arn:aws:bedrock-agentcore:{region}:{account_id}:runtime/*"
                ],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=cfg.gw_role,
        PolicyName="GatewayInvokeRuntime",
        PolicyDocument=json.dumps(gw_invoke),
    )
    gw_role_arn = f"arn:aws:iam::{account_id}:role/{cfg.gw_role}"
    log("  Sleeping 15s for Gateway role propagation...")
    time.sleep(15)

    # ---------------------------------------------------------------------
    # 8. Create the Gateway (MCP inbound, CUSTOM_JWT via Cognito)
    # ---------------------------------------------------------------------
    rep.begin(f"Gateway {cfg.gateway_name} (MCP · Custom-JWT)")
    authorizer_cfg = {
        "customJWTAuthorizer": {
            "discoveryUrl": discovery_url,
            "allowedClients": [client_id],
        }
    }
    gw_kwargs = dict(
        name=cfg.gateway_name,
        roleArn=gw_role_arn,
        protocolType="MCP",
        authorizerType="CUSTOM_JWT",
        authorizerConfiguration=authorizer_cfg,
    )
    if supports_param(agentcore, "CreateGateway", "tags"):
        gw_kwargs["tags"] = cfg.tags()
    try:
        gw = agentcore.create_gateway(**gw_kwargs)
        gateway_id = gw["gatewayId"]
    except ClientError as e:
        # Idempotent re-run: already exists -> look it up by name.
        gateway_id = _find_gateway_by_name(agentcore, cfg.gateway_name)
        if not gateway_id:
            raise
        log(f"  gateway already exists; reusing {gateway_id} ({err_code(e)})")
        # Self-heal stacks from the pre-fix era: if the reused gateway trusts a
        # client other than the one we just resolved (a duplicate-pool artifact),
        # re-point its authorizer or every token this build mints gets a 401.
        gw_detail = agentcore.get_gateway(gatewayIdentifier=gateway_id)
        allowed = (
            gw_detail.get("authorizerConfiguration", {})
            .get("customJWTAuthorizer", {})
            .get("allowedClients", [])
        )
        if client_id not in allowed:
            log("  reused gateway trusts a stale Cognito client -- updating the authorizer")
            agentcore.update_gateway(
                gatewayIdentifier=gateway_id,
                name=cfg.gateway_name,
                roleArn=gw_role_arn,
                protocolType="MCP",
                authorizerType="CUSTOM_JWT",
                authorizerConfiguration=authorizer_cfg,
            )

    poll(
        lambda: agentcore.get_gateway(gatewayIdentifier=gateway_id).get("status"),
        "READY",
        {"FAILED", "UPDATE_UNSUCCESSFUL"},
        attempts=60,
        delay=10,
        label="gateway",
    )
    gateway_url = agentcore.get_gateway(gatewayIdentifier=gateway_id)["gatewayUrl"]
    log(f"  gateway_url={gateway_url}")

    # ---------------------------------------------------------------------
    # 9. One gateway TARGET per runtime -- the gateway aggregates them all
    # ---------------------------------------------------------------------
    rep.begin("Gateway targets (one per runtime)")
    cred_provider_config = [
        {
            "credentialProviderType": "GATEWAY_IAM_ROLE",
            "credentialProvider": {
                "iamCredentialProvider": {
                    "service": "bedrock-agentcore",
                    "region": region,
                }
            },
        }
    ]
    for rt in runtimes:
        arn = rt["arn"]
        s = rt["server"]
        if not arn:
            continue
        # URL-encode the ARN (encode EVERYTHING, like jq '@uri').
        enc = urllib.parse.quote(arn, safe="")
        url = (
            f"https://bedrock-agentcore.{region}.amazonaws.com/runtimes/{enc}"
            "/invocations?qualifier=DEFAULT"
        )
        tgt = cfg.target_name(s)  # tools namespaced <tgt>___<tool>
        log(f"  -- target {tgt}  -> @chkp/{s}-mcp")
        try:
            agentcore.create_gateway_target(
                gatewayIdentifier=gateway_id,
                name=tgt,
                targetConfiguration={
                    "mcp": {"mcpServer": {"endpoint": url, "listingMode": "DEFAULT"}}
                },
                credentialProviderConfigurations=cred_provider_config,
            )
        except ClientError as e:
            if err_code(e) in ("ConflictException",) or "already" in str(e).lower():
                log(f"     target {tgt} already exists; skipping")
            else:
                log(f"     target {tgt} create failed: {err_code(e)} {e}")
                failures.append(f"target {tgt}: {err_code(e) or e}")
                rep.warn_current()

    # delete/create are async: wait for targets to settle. A target reaches a
    # TERMINAL state -- READY or FAILED -- so stop as soon as none are still
    # syncing (don't burn the whole budget waiting on a target that FAILED).
    terminal = {"READY", "FAILED", "CREATE_FAILED", "UPDATE_FAILED"}
    items = []
    for _ in range(60):
        items = list(paginate(agentcore.list_gateway_targets, gatewayIdentifier=gateway_id))
        pending = [t for t in items if t.get("status") not in terminal]
        if not pending:
            break
        log(f"    targets syncing ({len(pending)} not ready)...")
        time.sleep(10)
    # A FAILED target is a per-server problem (bad startup args, missing creds,
    # or a server that can't enumerate tools with placeholders) -- record it so
    # the deploy exits non-zero with a pointer, not a silent hang.
    failed = [t.get("name") for t in items if t.get("status") in (terminal - {"READY"})]
    for ft in failed:
        failures.append(f"target {ft}: FAILED to reach READY "
                        f"(check its runtime's CloudWatch logs)")
        rep.warn_current()

    # ---------------------------------------------------------------------
    # 10. Hosted agent runtime (default; skip with --no-agent) -- so
    #     `agent --runtime agentcore` is instant from the very first ask.
    # ---------------------------------------------------------------------
    agent_arn = None
    if include_agent:
        rep.begin("Hosted agent runtime")
        from . import hosting

        agent_arn, agent_err = hosting.provision(cfg, session)
        if agent_arn:
            log(f"  hosted agent runtime ready ({cfg.agent_runtime_name})")
        else:
            for line in agent_err or []:
                log(f"  {line}")
            failures.append("hosted agent runtime: provisioning failed "
                            "(local agent unaffected; retry with any "
                            "`agent --runtime agentcore` run)")
            rep.warn_current()

    # ---------------------------------------------------------------------
    # 11. Token + verify the AGGREGATED catalog through the gateway
    # ---------------------------------------------------------------------
    rep.begin("Cognito token + tools/list verify")
    access_token = cog.get_token(
        token_endpoint, client_id, client_secret, f"{cfg.res_server}/read"
    )

    catalog = None
    if not access_token:
        log("  WARNING: could not obtain a Cognito token yet (propagation delay?).")
        log("  The stack is UP; re-check shortly with: python3 -m chkpmcpaws status")
    else:
        catalog = mcpcheck.verify_tools_mcp(gateway_url, access_token)
    listed_ok = catalog is not None

    # ---------------------------------------------------------------------
    # STACK UP summary (printed by Reporter.close after the frame is sealed)
    # ---------------------------------------------------------------------
    if n_real >= len(cred_servers):
        secrets_line = (f"  Secrets     : all {len(cred_servers)} set with real creds "
                        "from --creds (chkp/<server>)")
    elif n_real:
        secrets_line = (f"  Secrets     : {n_real} of {len(cred_servers)} set with real "
                        "creds from --creds; the rest are placeholders (chkp/<server>)")
    else:
        secrets_line = (f"  Secrets     : {len(cred_servers)} per-server secret(s) ensured "
                        "(new ones get placeholders; existing values untouched)")
    summary = [
        ui.stack_up_banner(ok=True, partial=bool(failures))
        + f"  ·  {region}  ·  {len(cfg.servers)} servers",
        f"  Gateway URL : {gateway_url}",
        f"  Servers     : {' '.join(cfg.servers)}   (one Runtime + one target each, aggregated)",
        secrets_line,
        "  Status      : python3 -m chkpmcpaws status",
        "  Ask         : python3 -m chkpmcpaws chat \"how many hosts are configured?\"",
        "  Destroy     : python3 -m chkpmcpaws destroy",
    ]
    if agent_arn:
        summary.insert(5, "  Hosted agent: chkp_agent runtime ready -- "
                          "python3 -m chkpmcpaws chat --runtime agentcore \"...\"")
    if n_real < len(cred_servers):
        summary += [
            "  GO LIVE     : put real Check Point creds in and restart the runtimes:",
            "                  python3 -m chkpmcpaws creds template   # writes a creds file",
            "                  # fill it in, then:",
            "                  python3 -m chkpmcpaws creds apply       # writes secrets + refresh",
            "                (secrets are read once at container boot -- see go-live docs).",
        ]
    if catalog:
        summary += [""] + catalog
    if access_token and not listed_ok:
        summary += [
            "",
            "  tools/list verification skipped: the 'mcp' package is not installed.",
            "  For the full aggregated catalog:  python3 -m pip install mcp  then",
            "  python3 -m chkpmcpaws status   (or probe locally: node scripts/mcp_probe.mjs)",
        ]
    summary += ui.links_block(config.console_links(cfg, account_id,
                                                   gateway_id=gateway_id,
                                                   pool_id=pool_id,
                                                   include_agent=include_agent),
                              title="Open in the AWS Console:")
    if failures:
        summary += ["", "  PARTIAL FAILURE -- these steps did not complete:"]
        summary += [f"    - {f}" for f in failures]
        summary += ["  Re-running the deploy is safe (idempotent); or teardown and rebuild."]
    # A missing optional 'mcp' verifier is NOT a failure; missing runtimes or
    # targets are -- the exit code must never report a partial deploy as success.
    return (1 if failures else 0), True, summary


# =============================================================================
# Refresh -- restart the runtimes so they re-read the Secrets Manager secret.
# The entrypoint loads the secret into env ONCE at container boot, so a secret
# change (new Check Point creds) is invisible until the container cycles.
# update_agent_runtime keeps the SAME runtime id/ARN (gateway targets stay
# valid) but bumps the version, which cycles the container -> fresh secret read.
# =============================================================================
def refresh(cfg, session):
    region = cfg.region
    ac = agentcore_client(session, region)
    account_id = resolve_account(session, region)
    runtimes = [
        r for r in paginate(ac.list_agent_runtimes)
        if str(r.get("agentRuntimeName", "")).startswith(cfg.runtime_scan_prefix)
    ]
    if not runtimes:
        log(f"No {cfg.runtime_scan_prefix}* runtimes found -- deploy first: "
            "python3 -m chkpmcpaws deploy")
        return 1

    steps = [f"Restart {r['agentRuntimeName']}" for r in runtimes]
    rep = ui.Reporter("refresh", "REFRESH", steps, region)
    rep.set_context(f"acct {account_id} · {region} · re-reading Check Point secrets")
    ui.activate(rep)
    failures = []
    try:
        for r in runtimes:
            rep.begin()
            rid = r["agentRuntimeId"]
            log(f"restarting {r['agentRuntimeName']} so it re-reads its secret")
            try:
                d = ac.get_agent_runtime(agentRuntimeId=rid)
                # Full-replace PUT: re-send the create-time config unchanged;
                # the version bump is what cycles the container.
                ac.update_agent_runtime(
                    agentRuntimeId=rid,
                    agentRuntimeArtifact=d["agentRuntimeArtifact"],
                    roleArn=d["roleArn"],
                    networkConfiguration=d["networkConfiguration"],
                    protocolConfiguration=d["protocolConfiguration"],
                    environmentVariables=d["environmentVariables"],
                )
                ok = poll(
                    lambda rid=rid: ac.get_agent_runtime(agentRuntimeId=rid).get("status"),
                    "READY", {"UPDATE_FAILED", "CREATE_FAILED"},
                    attempts=40, delay=6, label=r["agentRuntimeName"],
                )
                if not ok:
                    failures.append(r["agentRuntimeName"])
                    rep.warn_current()
                else:
                    log("  READY (new version serving the current secret)")
            except (ClientError, BotoCoreError) as e:
                log(f"  restart failed: {err_code(e) or e}")
                failures.append(r["agentRuntimeName"])
                rep.warn_current()
    except BaseException:
        rep.fail_current()
        ui.deactivate()
        rep.close(ok=False, summary=["Refresh aborted -- see the log file."])
        raise
    ui.deactivate()
    done = len(runtimes) - len(failures)
    summary = [
        ui.done_banner("RUNTIMES REFRESHED", ok=not failures) + f"  ·  {region}",
        f"  {done}/{len(runtimes)} runtime(s) restarted; each re-read its Check Point secret.",
        "  Re-ask:  python3 -m chkpmcpaws chat \"how many hosts are configured?\"",
    ]
    if failures:
        summary.append("  Not refreshed: " + ", ".join(failures) + "  (re-run refresh).")
    rep.close(ok=not failures, summary=summary)
    return 1 if failures else 0


# =============================================================================
# Lookups (idempotent re-run helpers)
# =============================================================================
def _ensure_role(iam, name, trust, cfg):
    try:
        iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=json.dumps(trust),
            Tags=cfg.tags_kv(),
        )
    except ClientError as e:
        if err_code(e) != "EntityAlreadyExists":
            raise


def _find_runtime_by_name(agentcore, name):
    for rt in paginate(agentcore.list_agent_runtimes):
        if rt.get("agentRuntimeName") == name:
            return {"arn": rt.get("agentRuntimeArn"), "id": rt.get("agentRuntimeId")}
    return None


def _find_gateway_by_name(agentcore, name):
    for gw in paginate(agentcore.list_gateways):
        if gw.get("name") == name:
            return gw.get("gatewayId")
    return None
