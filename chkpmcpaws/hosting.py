"""Host the security-ops agent ON an AgentCore Runtime (`agent --runtime agentcore`).

This is the AWS-native / reference-architecture target: instead of running the
reason -> gateway -> guardrail -> tools loop in your shell, it runs the IDENTICAL
loop (chkpmcpaws.agent, via chkpmcpaws._hosting_server) inside a managed, scalable,
observable AgentCore Runtime. The CLI then just InvokeAgentRuntime's it.

It reuses the field-tested build machinery (CodeBuild -> ECR -> AgentCore Runtime)
that already stands up the MCP servers -- the only differences are a Python image
that packages this repo and serves the HTTP contract, and serverProtocol=HTTP.

LIVE-VALIDATED (2026-07-16, account 342469737784 / us-east-1): CodeBuild image
build, the GET /ping + POST /invocations :8080 contract, in-runtime gateway
discovery + Cognito token minting + Converse (real estate data returned, token
telemetry included), and InvokeAgentRuntime response parsing. Two fixes came out
of that validation and are baked in below:
  * CreateAgentRuntime validates image access WITH the exec role at create time
    -> the role needs ecr:GetAuthorizationToken/BatchGetImage/GetDownloadUrlForLayer
  * the in-runtime agent runs the same gateway discovery as local
    -> the role needs bedrock-agentcore:ListGateways/GetGateway
Memory division of labor (by design): the exec role has the memory DATA plane
(attach to an existing memory, recall, save -- live-validated) but no iam:*, so
only a local `agent --session` run (or the deployer) can CREATE the memory.
"""

import json
import os
import shutil
import tempfile
import time
import zipfile

from .awsutil import (
    ClientError,
    agentcore_client,
    agentcore_data_client,
    err_code,
    log,
    poll,
    resolve_account,
    supports_param,
)

AGENT_DOCKERFILE = r"""FROM --platform=linux/arm64 public.ecr.aws/docker/library/python:3.12-slim
WORKDIR /app
COPY chkpmcpaws /app/chkpmcpaws
RUN pip install --no-cache-dir boto3 mcp certifi
ENV PORT=8080
EXPOSE 8080
CMD ["python", "-m", "chkpmcpaws._hosting_server"]
"""


def _buildspec(region, account_id, image_uri):
    login = (f"aws ecr get-login-password --region {region} | docker login "
             f"--username AWS --password-stdin {account_id}.dkr.ecr.{region}.amazonaws.com")
    return (
        "version: 0.2\n"
        "phases:\n"
        f'  pre_build: {{commands: ["{login}"]}}\n'
        f'  build: {{commands: ["docker build -t {image_uri} .","docker push {image_uri}"]}}\n'
    )


def _package_source(dest_dir):
    """Copy this repo's chkpmcpaws package into the build context (minus caches and
    tests) so the image can `python -m chkpmcpaws._hosting_server`."""
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    shutil.copytree(
        pkg_dir,
        os.path.join(dest_dir, "chkpmcpaws"),
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "tests"),
    )


def _exec_role_docs(cfg, account_id, region):
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AgentAssumeRole",
            "Effect": "Allow",
            "Principal": {"Service": "bedrock-agentcore.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {"aws:SourceAccount": account_id},
                "ArnLike": {"aws:SourceArn": f"arn:aws:bedrock-agentcore:{region}:{account_id}:*"},
            },
        }],
    }
    perms = {
        "Version": "2012-10-17",
        "Statement": [
            {
                # CreateAgentRuntime validates image access WITH THIS ROLE at
                # create time (live-verified: ValidationException naming these
                # three actions when they are missing).
                "Sid": "ECRPullAgentImage",
                "Effect": "Allow",
                "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
                "Resource": f"arn:aws:ecr:{region}:{account_id}:repository/{cfg.agent_ecr_repo}",
            },
            {
                "Sid": "ECRAuth",
                "Effect": "Allow",
                "Action": "ecr:GetAuthorizationToken",
                "Resource": "*",
            },
            {
                "Sid": "InvokeBedrock",
                "Effect": "Allow",
                "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
                "Resource": [
                    f"arn:aws:bedrock:{region}::foundation-model/*",
                    f"arn:aws:bedrock:{region}:{account_id}:inference-profile/*",
                    "arn:aws:bedrock:*::foundation-model/*",
                ],
            },
            {
                "Sid": "MintGatewayToken",
                "Effect": "Allow",
                "Action": [
                    "cognito-idp:ListUserPools",
                    "cognito-idp:ListUserPoolClients",
                    "cognito-idp:DescribeUserPoolClient",
                    "cognito-idp:DescribeResourceServer",
                ],
                "Resource": "*",
            },
            {
                "Sid": "WorkloadIdentity",
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
                # The in-runtime agent runs the SAME discovery as local:
                # list_gateways + get_gateway (live-verified failure without it).
                # Control-plane reads stay on * -- ids are service-generated.
                "Sid": "DiscoverGateway",
                "Effect": "Allow",
                "Action": ["bedrock-agentcore:ListGateways", "bedrock-agentcore:GetGateway"],
                "Resource": "*",
            },
            {
                # Attach to an EXISTING AgentCore Memory (created by a local
                # `agent --session` run). Deliberately NO iam:* here, so the
                # hosted path can never create the memory role itself --
                # creation stays a local/deployer action.
                "Sid": "AttachExistingMemory",
                "Effect": "Allow",
                "Action": [
                    "bedrock-agentcore:ListMemories",
                    "bedrock-agentcore:GetMemory",
                    "bedrock-agentcore:CreateEvent",
                    "bedrock-agentcore:RetrieveMemoryRecords",
                ],
                "Resource": "*",
            },
            {
                # Read the agent-side Gaia login secret to answer the Gaia
                # server's elicitation (chkpmcpaws.gaia). Scoped to that one secret.
                "Sid": "ReadGaiaCreds",
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": f"arn:aws:secretsmanager:{region}:{account_id}:secret:{cfg.secret_name('quantum-gaia')}*",
            },
            {
                "Sid": "Logs",
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            {
                "Sid": "Metrics",
                "Effect": "Allow",
                "Action": "cloudwatch:PutMetricData",
                "Resource": "*",
                "Condition": {"StringEquals": {"cloudwatch:namespace": "bedrock-agentcore"}},
            },
        ],
    }
    return trust, perms


def provision(cfg, session):
    """Build the agent image and create/return the hosted AgentCore Runtime ARN.
    Idempotent: reuses an existing runtime/repo/role. Returns (arn, None) on
    success or (None, [error lines]) on failure."""
    region = cfg.region
    agentcore = agentcore_client(session, region)
    account_id = resolve_account(session, region)
    iam = session.client("iam", region_name=region)
    ecr = session.client("ecr", region_name=region)
    s3 = session.client("s3", region_name=region)
    codebuild = session.client("codebuild", region_name=region)

    existing = _find_runtime(agentcore, cfg.agent_runtime_name)
    if existing:
        # Refresh the exec-role policy even on reuse, so permission fixes land
        # without recreating the runtime (role changes apply live).
        trust, perms = _exec_role_docs(cfg, account_id, region)
        from .build import _ensure_role
        _ensure_role(iam, cfg.agent_role, trust, cfg)
        iam.put_role_policy(RoleName=cfg.agent_role, PolicyName="AgentRuntimeExec",
                            PolicyDocument=json.dumps(perms))
        log(f"  hosted agent runtime already exists ({existing['id']}); reusing "
            "(exec-role policy refreshed).")
        return existing["arn"], None

    image_uri = cfg.agent_image_uri(account_id)
    src_bucket = cfg.src_bucket(account_id)
    cb_project = cfg.cb_project + "-agent"

    # --- container source (this repo + Dockerfile + buildspec) --------------
    src_dir = tempfile.mkdtemp(prefix="chkp-agent-")
    _package_source(src_dir)
    for fname, content in (
        ("Dockerfile", AGENT_DOCKERFILE),
        ("buildspec.yml", _buildspec(region, account_id, image_uri)),
    ):
        with open(os.path.join(src_dir, fname), "w", newline="\n") as fh:
            fh.write(content)
    zip_path = os.path.join(src_dir, "agent-src.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(os.path.join(src_dir, "chkpmcpaws")):
            for f in files:
                full = os.path.join(root, f)
                zf.write(full, arcname=os.path.relpath(full, src_dir))
        zf.write(os.path.join(src_dir, "Dockerfile"), "Dockerfile")
        zf.write(os.path.join(src_dir, "buildspec.yml"), "buildspec.yml")

    try:
        ecr.create_repository(repositoryName=cfg.agent_ecr_repo, tags=cfg.tags_kv())
    except ClientError as e:
        if err_code(e) != "RepositoryAlreadyExistsException":
            raise

    # --- CodeBuild service role (reuse the MCP build role -- same scope) -----
    from .build import _ensure_role

    cb_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "codebuild.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    _ensure_role(iam, cfg.cb_role, cb_trust, cfg)
    cb_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "EcrAuth", "Effect": "Allow",
             "Action": "ecr:GetAuthorizationToken", "Resource": "*"},
            {"Sid": "EcrPushPull", "Effect": "Allow",
             "Action": ["ecr:BatchCheckLayerAvailability", "ecr:CompleteLayerUpload",
                        "ecr:InitiateLayerUpload", "ecr:PutImage", "ecr:UploadLayerPart",
                        "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
             "Resource": [f"arn:aws:ecr:{region}:{account_id}:repository/{cfg.ecr_repo}",
                          f"arn:aws:ecr:{region}:{account_id}:repository/{cfg.agent_ecr_repo}"]},
            {"Sid": "Logs", "Effect": "Allow",
             "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
             # Prefix covers BOTH the MCP build and this -agent build, so reusing
             # the shared CodeBuild role never narrows the MCP build's log perms.
             "Resource": f"arn:aws:logs:{region}:{account_id}:log-group:/aws/codebuild/{cfg.cb_project}*"},
            {"Sid": "Src", "Effect": "Allow",
             "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket",
                        "s3:GetBucketLocation"],
             "Resource": [f"arn:aws:s3:::{src_bucket}", f"arn:aws:s3:::{src_bucket}/*"]},
        ],
    }
    iam.put_role_policy(RoleName=cfg.cb_role, PolicyName="ChkpMcpCodeBuildScoped",
                        PolicyDocument=json.dumps(cb_policy))
    cb_role_arn = f"arn:aws:iam::{account_id}:role/{cfg.cb_role}"

    # --- upload source + build ----------------------------------------------
    try:
        if region == "us-east-1":
            s3.create_bucket(Bucket=src_bucket)
        else:
            s3.create_bucket(Bucket=src_bucket,
                             CreateBucketConfiguration={"LocationConstraint": region})
    except ClientError as e:
        if err_code(e) not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise
    s3.upload_file(zip_path, src_bucket, "agent-src.zip")

    log("  waiting 15s for CodeBuild role propagation...")
    time.sleep(15)
    try:
        codebuild.create_project(
            name=cb_project,
            source={"type": "S3", "location": f"{src_bucket}/agent-src.zip"},
            artifacts={"type": "NO_ARTIFACTS"},
            environment={
                "type": "ARM_CONTAINER",
                "image": "aws/codebuild/amazonlinux2-aarch64-standard:3.0",
                "computeType": "BUILD_GENERAL1_SMALL",
                "privilegedMode": True,
            },
            serviceRole=cb_role_arn,
            tags=cfg.tags_kv(key="key", value="value"),
        )
    except ClientError as e:
        if err_code(e) != "ResourceAlreadyExistsException":
            raise
    build_id = codebuild.start_build(projectName=cb_project)["build"]["id"]
    log(f"  CodeBuild {build_id} -- waiting for SUCCEEDED...")
    while True:
        try:
            status = codebuild.batch_get_builds(ids=[build_id])["builds"][0]["buildStatus"]
        except (ClientError, IndexError, KeyError):
            status = "IN_PROGRESS"
        log(f"    {status}")
        if status == "SUCCEEDED":
            break
        if status in ("FAILED", "FAULT", "STOPPED", "TIMED_OUT"):
            return None, [f"agent image build ended {status} -- inspect CodeBuild "
                          f"project {cb_project}."]
        time.sleep(15)

    # --- agent exec role + runtime ------------------------------------------
    trust, perms = _exec_role_docs(cfg, account_id, region)
    _ensure_role(iam, cfg.agent_role, trust, cfg)
    iam.put_role_policy(RoleName=cfg.agent_role, PolicyName="AgentRuntimeExec",
                        PolicyDocument=json.dumps(perms))
    agent_role_arn = f"arn:aws:iam::{account_id}:role/{cfg.agent_role}"
    log("  waiting 10s for agent exec-role propagation...")
    time.sleep(10)

    env = {"AWS_REGION": region, "CHKP_PREFIX": cfg.prefix or ""}
    kwargs = dict(
        agentRuntimeName=cfg.agent_runtime_name,
        agentRuntimeArtifact={"containerConfiguration": {"containerUri": image_uri}},
        roleArn=agent_role_arn,
        networkConfiguration={"networkMode": "PUBLIC"},
        protocolConfiguration={"serverProtocol": "HTTP"},
        environmentVariables=env,
    )
    if supports_param(agentcore, "CreateAgentRuntime", "tags"):
        kwargs["tags"] = cfg.tags()
    try:
        resp = agentcore.create_agent_runtime(**kwargs)
        arn, rid = resp["agentRuntimeArn"], resp["agentRuntimeId"]
    except ClientError as e:
        found = _find_runtime(agentcore, cfg.agent_runtime_name)
        if not found:
            detail = (e.response.get("Error", {}).get("Message") or "")[:300]
            return None, [f"CreateAgentRuntime failed: {err_code(e) or e}"
                          + (f" -- {detail}" if detail else "")]
        arn, rid = found["arn"], found["id"]

    ok = poll(lambda: agentcore.get_agent_runtime(agentRuntimeId=rid).get("status"),
              "READY", {"CREATE_FAILED", "UPDATE_FAILED"}, attempts=80, delay=10,
              label="hosted agent runtime")
    if not ok:
        return None, ["hosted agent runtime did not reach READY -- check its status/logs."]
    return arn, None


def invoke(cfg, session, task, session_id=None, actor=None):
    """Provision (first use) then InvokeAgentRuntime with the task. Returns
    (result_dict, None) or (None, [error lines])."""
    arn, err = provision(cfg, session)
    if not arn:
        return None, err
    data = agentcore_data_client(session, cfg.region)
    payload = {"prompt": task}
    if session_id:
        payload["sessionId"] = session_id
    if actor:
        payload["actor"] = actor
    rsid = _runtime_session_id(session_id)
    try:
        resp = data.invoke_agent_runtime(
            agentRuntimeArn=arn,
            runtimeSessionId=rsid,
            contentType="application/json",
            accept="application/json",
            payload=json.dumps(payload).encode("utf-8"),
        )
    except ClientError as e:
        return None, [f"InvokeAgentRuntime failed: {err_code(e) or e}"]
    body = resp.get("response")
    raw = body.read() if hasattr(body, "read") else (body or b"")
    try:
        return json.loads(raw.decode("utf-8")), None
    except (ValueError, UnicodeDecodeError):
        return {"result": raw.decode("utf-8", "replace")}, None


def _runtime_session_id(session_id):
    """AgentCore requires a runtimeSessionId of 33-100 chars. Derive one that is
    stable per --session so multi-turn invokes share a runtime session.

    The 'chkpmcp-' prefix is a WIRE-LEVEL identifier, deliberately NOT renamed
    with the tool: changing it would change the runtimeSessionId a resumed
    --session presents, splitting warm-runtime affinity and session-grouped
    observability across the upgrade."""
    base = "chkpmcp-session-" + (session_id or "default")
    base = "".join(c if (c.isalnum() or c in "-_") else "-" for c in base)
    if len(base) < 33:
        base = (base + "-" + "0" * 33)[:40]
    return base[:100]


def _find_runtime(agentcore, name):
    from .build import _find_runtime_by_name

    return _find_runtime_by_name(agentcore, name)


def destroy_extras(cfg, session):
    """Remove the hosting-only leftovers the MCP teardown doesn't cover: the
    agent's ECR repo, its exec role, and the -agent CodeBuild project. (The
    runtime itself is named chkp_*, so the MCP runtime scan already deletes it.)
    Returns a short status string or None."""
    region = cfg.region
    removed = []
    ecr = session.client("ecr", region_name=region)
    try:
        ecr.delete_repository(repositoryName=cfg.agent_ecr_repo, force=True)
        removed.append(f"ECR {cfg.agent_ecr_repo}")
    except ClientError:
        pass
    codebuild = session.client("codebuild", region_name=region)
    try:
        codebuild.delete_project(name=cfg.cb_project + "-agent")
        removed.append(f"CodeBuild {cfg.cb_project}-agent")
    except ClientError:
        pass
    iam = session.client("iam", region_name=region)
    try:
        iam.delete_role_policy(RoleName=cfg.agent_role, PolicyName="AgentRuntimeExec")
    except ClientError:
        pass
    try:
        iam.delete_role(RoleName=cfg.agent_role)
        removed.append(f"role {cfg.agent_role}")
    except ClientError:
        pass
    return ", ".join(removed) if removed else None
