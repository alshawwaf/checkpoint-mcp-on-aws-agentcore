"""HTTPS bridge for the hosted agent -- `chkpmcpaws bridge {provision,show,destroy}`.

Postman and other AWS-aware clients can call the hosted agent directly with
SigV4 (POST /runtimes/<arn>/invocations on the bedrock-agentcore endpoint; see
`bridge show`). Everything else -- Microsoft Teams via Power Automate, n8n,
plain curl, webhooks -- gets this bridge: an API Gateway REST endpoint backed
by one Lambda:

    POST {url}   Authorization: Bearer <token>   {"prompt": "...", "session": "..."}

It verifies the token (generated at provision, stored ONLY in AWS Secrets
Manager -- never in code or logs), invokes the hosted agent runtime, strips
model scaffolding tags, and returns {"result": ..., "usage": ...}.

Design notes (live-derived):
  * API Gateway fronts the Lambda instead of a Function URL -- anonymous
    Function URL invokes were platform-403'd on the validation account, and a
    NONE-auth URL also reserves the Authorization header for SigV4. API
    Gateway has neither problem and accepts an extended integration timeout.
  * Auth (org policy: every endpoint requires authentication): the FIRST thing
    the handler does is a constant-time token check -- `Authorization: Bearer`
    or `X-Bridge-Token`, either works. Rotating the token = write a new value
    to the secret; the handler picks it up within TOKEN_TTL seconds.
"""

import io
import json
import secrets as pysecrets
import time
import zipfile

from .awsutil import (
    ClientError,
    agentcore_client,
    err_code,
    log,
    paginate,
    resolve_account,
)

# The Lambda handler. Stdlib + boto3 only (both preinstalled in the Lambda
# python3.12 runtime). Kept as a string so provisioning needs no build step.
HANDLER_PY = r'''"""chkpmcpaws agent bridge -- bearer-token HTTPS front for the hosted agent."""
import hmac
import json
import os
import re
import time

import boto3

RUNTIME_ARN = os.environ["RUNTIME_ARN"]
SECRET_ARN = os.environ["SECRET_ARN"]
TOKEN_TTL = 300  # re-read the secret at most every 5 minutes (rotation window)

_token = {"value": None, "at": 0.0}
_sm = boto3.client("secretsmanager")
_ac = boto3.client("bedrock-agentcore")


def _bearer_token():
    now = time.time()
    if _token["value"] is None or now - _token["at"] > TOKEN_TTL:
        raw = _sm.get_secret_value(SecretId=SECRET_ARN)["SecretString"]
        _token["value"] = json.loads(raw)["token"]
        _token["at"] = now
    return _token["value"]


def _resp(code, obj):
    return {"statusCode": code, "headers": {"Content-Type": "application/json"},
            "body": json.dumps(obj)}


def _session_id(session):
    # 'chkpmcp-' is a wire-level runtimeSessionId prefix, deliberately NOT
    # renamed with the tool: it must keep matching what the already-deployed
    # bridge Lambda sends so resumed sessions keep their runtime affinity.
    base = "chkpmcp-bridge-" + (session or "default")
    base = "".join(c if (c.isalnum() or c in "-_") else "-" for c in base)
    if len(base) < 33:
        base = (base + "-" + "0" * 33)[:40]
    return base[:100]


def _clean(text):
    # Strip model scaffolding (Nova's <thinking>/<response>) at the API boundary.
    text = re.sub(r"<thinking>.*?</thinking>", "", text or "", flags=re.S)
    return re.sub(r"</?response>", "", text).strip()


def handler(event, _ctx):
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    token = _bearer_token()
    auth = headers.get("authorization") or ""
    candidates = [headers.get("x-bridge-token") or ""]
    if auth.startswith("Bearer "):
        candidates.append(auth[7:])
    if not any(c and hmac.compare_digest(c, token) for c in candidates):
        return _resp(401, {"error": "unauthorized (send Authorization: Bearer "
                                    "<token> or X-Bridge-Token)"})

    body = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        import base64
        body = base64.b64decode(body).decode("utf-8", "replace")
    try:
        payload = json.loads(body)
    except ValueError:
        return _resp(400, {"error": "body must be JSON"})
    prompt = ""
    for key in ("prompt", "task", "text", "question"):
        v = payload.get(key)
        if isinstance(v, str) and v.strip():
            prompt = v.strip()
            break
    if not prompt:
        return _resp(400, {"error": "no prompt in body (use {\"prompt\": \"...\"})"})

    fwd = {"prompt": prompt}
    if payload.get("session"):
        fwd["sessionId"] = str(payload["session"])
    if payload.get("actor"):
        fwd["actor"] = str(payload["actor"])
    try:
        resp = _ac.invoke_agent_runtime(
            agentRuntimeArn=RUNTIME_ARN,
            runtimeSessionId=_session_id(payload.get("session")),
            contentType="application/json",
            accept="application/json",
            payload=json.dumps(fwd).encode("utf-8"),
        )
        raw = resp.get("response")
        raw = raw.read() if hasattr(raw, "read") else (raw or b"")
        out = json.loads(raw.decode("utf-8"))
    except Exception as e:  # noqa: BLE001 -- surface a clean 502, never a stack
        return _resp(502, {"error": f"agent invoke failed: {type(e).__name__}"})
    return _resp(200, {
        "result": _clean(str(out.get("result", ""))),
        "usage": out.get("usage"),
        "model": out.get("model"),
        "error": bool(out.get("error")),
    })
'''


def _zip_handler():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("lambda_function.py")
        info.external_attr = 0o644 << 16
        zf.writestr(info, HANDLER_PY)
    return buf.getvalue()


def _runtime_arn(cfg, session):
    ac = agentcore_client(session, cfg.region)
    for rt in paginate(ac.list_agent_runtimes):
        if rt.get("agentRuntimeName") == cfg.agent_runtime_name:
            return rt.get("agentRuntimeArn")
    return None


def provision(cfg, session):
    """Create/refresh the bridge: secret (token), role, Lambda, Function URL.
    Idempotent. Returns exit code."""
    region = cfg.region
    account_id = resolve_account(session, region)
    lam = session.client("lambda", region_name=region)
    iam = session.client("iam", region_name=region)
    sm = session.client("secretsmanager", region_name=region)

    arn = _runtime_arn(cfg, session)
    if not arn:
        log("No hosted agent runtime found -- deploy first (python3 -m chkpmcpaws deploy).")
        return 1

    # --- bearer token secret (create once; keep existing token on re-runs) ---
    token = None
    try:
        sm.create_secret(Name=cfg.bridge_secret,
                         SecretString=json.dumps({"token": pysecrets.token_urlsafe(32)}),
                         Tags=cfg.tags_kv())
        log(f"[secret] created {cfg.bridge_secret} (holds the bearer token)")
    except ClientError as e:
        if err_code(e) == "InvalidRequestException" and "deletion" in str(e).lower():
            sm.restore_secret(SecretId=cfg.bridge_secret)
            sm.put_secret_value(SecretId=cfg.bridge_secret,
                                SecretString=json.dumps({"token": pysecrets.token_urlsafe(32)}))
            log(f"[secret] restored {cfg.bridge_secret} with a fresh token")
        elif err_code(e) != "ResourceExistsException":
            raise
        else:
            log(f"[secret] {cfg.bridge_secret} exists -- token unchanged")
    secret_arn = sm.describe_secret(SecretId=cfg.bridge_secret)["ARN"]

    # --- execution role ------------------------------------------------------
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
        "Action": "sts:AssumeRole"}]}
    perms = {"Version": "2012-10-17", "Statement": [
        {"Sid": "Logs", "Effect": "Allow",
         "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": f"arn:aws:logs:{region}:{account_id}:log-group:/aws/lambda/{cfg.bridge_fn}*"},
        {"Sid": "ReadToken", "Effect": "Allow",
         "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn},
        {"Sid": "InvokeAgent", "Effect": "Allow",
         "Action": "bedrock-agentcore:InvokeAgentRuntime",
         "Resource": [arn, f"{arn}/runtime-endpoint/*"]},
    ]}
    created_role = False
    try:
        iam.create_role(RoleName=cfg.bridge_role,
                        AssumeRolePolicyDocument=json.dumps(trust), Tags=cfg.tags_kv())
        created_role = True
        log(f"[iam] created role {cfg.bridge_role}")
    except ClientError as e:
        if err_code(e) != "EntityAlreadyExists":
            raise
    iam.put_role_policy(RoleName=cfg.bridge_role, PolicyName="AgentBridgeExec",
                        PolicyDocument=json.dumps(perms))
    role_arn = f"arn:aws:iam::{account_id}:role/{cfg.bridge_role}"
    if created_role:
        log("[iam] waiting 12s for role propagation...")
        time.sleep(12)

    # --- Lambda + Function URL -----------------------------------------------
    env = {"Variables": {"RUNTIME_ARN": arn, "SECRET_ARN": secret_arn}}
    code = _zip_handler()
    fn_arn = None
    for attempt in range(4):
        try:
            fn_arn = lam.create_function(
                FunctionName=cfg.bridge_fn, Runtime="python3.12",
                Role=role_arn, Handler="lambda_function.handler",
                Code={"ZipFile": code}, Timeout=300, MemorySize=256,
                Environment=env, Tags=cfg.tags(),
            )["FunctionArn"]
            log(f"[lambda] created {cfg.bridge_fn}")
            break
        except ClientError as e:
            if err_code(e) == "ResourceConflictException":
                lam.update_function_code(FunctionName=cfg.bridge_fn, ZipFile=code)
                _wait_fn_updated(lam, cfg.bridge_fn)
                lam.update_function_configuration(
                    FunctionName=cfg.bridge_fn, Role=role_arn, Timeout=300,
                    MemorySize=256, Environment=env)
                fn_arn = lam.get_function(FunctionName=cfg.bridge_fn)["Configuration"]["FunctionArn"]
                log(f"[lambda] updated {cfg.bridge_fn}")
                break
            # A brand-new role can be rejected by CreateFunction for a few
            # seconds ("role defined for the function cannot be assumed").
            if "assumed" in str(e).lower() and attempt < 3:
                log("[lambda] role not assumable yet -- retrying in 10s")
                time.sleep(10)
                continue
            raise

    url = _ensure_api(cfg, session, account_id, fn_arn)

    log("")
    log("Bridge is up. The endpoint requires the bearer token on every call:")
    _print_usage(cfg, url)
    return 0


def _find_api(apigw, name):
    pos = None
    while True:
        kw = {"position": pos} if pos else {}
        page = apigw.get_rest_apis(limit=100, **kw)
        for item in page.get("items", []):
            if item.get("name") == name:
                return item["id"]
        pos = page.get("position")
        if not pos:
            return None


def _ensure_api(cfg, session, account_id, fn_arn):
    """Find-or-create the REST API -> ANY / -> Lambda proxy, deployed to /prod.
    Integration timeout is raised as far as the account allows (agent runs can
    exceed API Gateway's classic 29s default)."""
    region = cfg.region
    apigw = session.client("apigateway", region_name=region)
    lam = session.client("lambda", region_name=region)

    api_id = _find_api(apigw, cfg.bridge_fn)
    if not api_id:
        api_id = apigw.create_rest_api(
            name=cfg.bridge_fn,
            description="Bearer-token HTTPS front for the chkpmcpaws hosted agent",
            endpointConfiguration={"types": ["REGIONAL"]},
            tags=cfg.tags(),
        )["id"]
        log(f"[apigw] created REST API {api_id}")
    root_id = next(r["id"] for r in apigw.get_resources(restApiId=api_id)["items"]
                   if r.get("path") == "/")
    try:
        apigw.put_method(restApiId=api_id, resourceId=root_id, httpMethod="ANY",
                         authorizationType="NONE")
    except ClientError as e:
        if err_code(e) != "ConflictException":
            raise
    integration_uri = (f"arn:aws:apigateway:{region}:lambda:path/2015-03-31/"
                       f"functions/{fn_arn}/invocations")
    # Try an extended integration timeout first (agent runs are long); fall
    # back to the classic 29s ceiling if this account doesn't allow it yet.
    for timeout_ms in (180000, 29000):
        try:
            apigw.put_integration(restApiId=api_id, resourceId=root_id,
                                  httpMethod="ANY", type="AWS_PROXY",
                                  integrationHttpMethod="POST",
                                  uri=integration_uri, timeoutInMillis=timeout_ms)
            if timeout_ms == 29000:
                log("[apigw] integration timeout capped at 29s on this account; "
                    "long multi-tool questions may time out -- ask AWS support "
                    "to raise the API Gateway integration timeout quota")
            break
        except ClientError as e:
            if timeout_ms == 29000 or "timeout" not in str(e).lower():
                raise
    apigw.create_deployment(restApiId=api_id, stageName="prod")
    try:
        lam.add_permission(FunctionName=cfg.bridge_fn, StatementId="AllowApiGw",
                           Action="lambda:InvokeFunction",
                           Principal="apigateway.amazonaws.com",
                           SourceArn=f"arn:aws:execute-api:{region}:{account_id}:{api_id}/*")
    except ClientError as e:
        if err_code(e) != "ResourceConflictException":
            raise
    return f"https://{api_id}.execute-api.{region}.amazonaws.com/prod"


def _wait_fn_updated(lam, name, attempts=30, delay=2):
    for _ in range(attempts):
        st = lam.get_function(FunctionName=name)["Configuration"].get("LastUpdateStatus")
        if st != "InProgress":
            return
        time.sleep(delay)


def _print_usage(cfg, url):
    log(f"  URL   : {url}")
    log(f"  Token : in Secrets Manager '{cfg.bridge_secret}' (JSON key 'token'):")
    log(f"          aws secretsmanager get-secret-value --secret-id '{cfg.bridge_secret}' "
        "--query SecretString --output text")
    log("  curl  : TOKEN=$(aws secretsmanager get-secret-value --secret-id "
        f"'{cfg.bridge_secret}' --query SecretString --output text | python3 -c "
        "'import sys,json;print(json.load(sys.stdin)[\"token\"])')")
    log(f"          curl -s -X POST '{url}' -H \"Authorization: Bearer $TOKEN\" "
        "-H 'Content-Type: application/json' "
        "-d '{\"prompt\": \"how many hosts are configured?\"}'")
    log("  Body  : {\"prompt\": \"...\", \"session\": \"optional\", \"actor\": \"optional\"}")
    log("  Header: Authorization: Bearer <token>   (X-Bridge-Token works too)")


def show(cfg, session, reveal=False):
    """Print the bridge URL + usage (and the token with --reveal-token)."""
    apigw = session.client("apigateway", region_name=cfg.region)
    api_id = _find_api(apigw, cfg.bridge_fn)
    if not api_id:
        log("Bridge not provisioned. Run: python3 -m chkpmcpaws bridge provision")
        return 1
    url = f"https://{api_id}.execute-api.{cfg.region}.amazonaws.com/prod"
    _print_usage(cfg, url)
    if reveal:
        sm = session.client("secretsmanager", region_name=cfg.region)
        token = json.loads(sm.get_secret_value(
            SecretId=cfg.bridge_secret)["SecretString"])["token"]
        log(f"  Bearer: {token}")
    # The SigV4 alternative for AWS-aware clients (Postman etc.)
    arn = _runtime_arn(cfg, session)
    if arn:
        import urllib.parse
        enc = urllib.parse.quote(arn, safe="")
        log("")
        log("  Direct SigV4 (Postman 'AWS Signature', service bedrock-agentcore):")
        log(f"    POST https://bedrock-agentcore.{cfg.region}.amazonaws.com/runtimes/{enc}/invocations?qualifier=DEFAULT")
        log("    header X-Amzn-Bedrock-AgentCore-Runtime-Session-Id: <any 33+ chars>")
        log("    body   {\"prompt\": \"how many hosts are configured?\"}")
    return 0


def destroy(cfg, session):
    """Remove the bridge (API, Lambda, role, secret). Idempotent."""
    apigw = session.client("apigateway", region_name=cfg.region)
    lam = session.client("lambda", region_name=cfg.region)
    iam = session.client("iam", region_name=cfg.region)
    sm = session.client("secretsmanager", region_name=cfg.region)
    removed = []
    api_id = None
    try:
        api_id = _find_api(apigw, cfg.bridge_fn)
    except ClientError:
        pass
    if api_id:
        try:
            apigw.delete_rest_api(restApiId=api_id)
            removed.append(f"API {api_id}")
        except ClientError:
            pass
    for call, label in (
        (lambda: lam.delete_function_url_config(FunctionName=cfg.bridge_fn), None),
        (lambda: lam.delete_function(FunctionName=cfg.bridge_fn), f"lambda {cfg.bridge_fn}"),
        (lambda: iam.delete_role_policy(RoleName=cfg.bridge_role, PolicyName="AgentBridgeExec"), None),
        (lambda: iam.delete_role(RoleName=cfg.bridge_role), f"role {cfg.bridge_role}"),
        (lambda: sm.delete_secret(SecretId=cfg.bridge_secret, RecoveryWindowInDays=7),
         f"secret {cfg.bridge_secret} (7-day recovery)"),
    ):
        try:
            call()
            if label:
                removed.append(label)
        except ClientError:
            pass
    if removed:
        log("[bridge] removed: " + ", ".join(removed))
    else:
        log("[bridge] nothing to remove.")
    return 0


def describe(cfg, session):
    """For verify/destroy-inventory: {'present': bool, 'url': str|None}."""
    try:
        apigw = session.client("apigateway", region_name=cfg.region)
        api_id = _find_api(apigw, cfg.bridge_fn)
    except ClientError:
        api_id = None
    if not api_id:
        return {"present": False, "url": None}
    return {"present": True,
            "url": f"https://{api_id}.execute-api.{cfg.region}.amazonaws.com/prod"}
