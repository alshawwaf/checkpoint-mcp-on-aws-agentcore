"""Shared AWS plumbing: session/client creation, error helpers, pagination,
waiters, tagging introspection, IAM role deletion, and the TLS context for
stdlib HTTPS calls. boto3 is the only hard dependency of the whole package."""

import os
import ssl
import sys
import time

try:
    import boto3
    from botocore.exceptions import (  # noqa: F401  (re-exported for callers)
        BotoCoreError,
        ClientError,
        NoCredentialsError,
        ProfileNotFound,
        UnknownServiceError,
    )
except ImportError:  # pragma: no cover
    sys.stderr.write("FATAL: boto3 is required.  Install it with:  pip install boto3\n")
    sys.exit(1)


_LOG_SINK = None


def set_log_sink(fn):
    """Route log() through a UI reporter (chkpmcpaws.ui). None restores print."""
    global _LOG_SINK
    _LOG_SINK = fn


def has_log_sink():
    """True when log() is routed through a UI reporter (deploy/destroy full-screen
    mode). The agent uses this to decide whether it can stream tokens straight to
    stdout or must buffer and emit whole lines through the sink."""
    return _LOG_SINK is not None


def log(msg=""):
    if _LOG_SINK is not None:
        _LOG_SINK(msg)
    else:
        print(msg, flush=True)


_TLS_CONTEXT = None


def _ca_bundle_candidates():
    try:
        import certifi

        yield certifi.where()
    except ImportError:
        pass
    try:
        import botocore

        p = os.path.join(os.path.dirname(botocore.__file__), "cacert.pem")
        if os.path.exists(p):
            yield p
    except ImportError:
        pass


def tls_context():
    """TLS context for the package's stdlib HTTPS calls (Cognito token, MCP
    probe fallback). Certificate verification is ALWAYS on.

    python.org macOS Python builds ship an OpenSSL whose default trust store
    is EMPTY unless 'Install Certificates.command' was run -- every stdlib
    HTTPS call then dies with CERTIFICATE_VERIFY_FAILED even though boto3
    works fine (botocore bundles its own CAs). When the default store has no
    CAs, fall back to the certifi bundle (installed with the 'mcp' extra) or
    botocore's bundled cacert.pem. Verification is never disabled.
    """
    global _TLS_CONTEXT
    if _TLS_CONTEXT is not None:
        return _TLS_CONTEXT
    ctx = ssl.create_default_context()
    if not ctx.cert_store_stats().get("x509_ca"):
        for cafile in _ca_bundle_candidates():
            try:
                candidate = ssl.create_default_context(cafile=cafile)
            except (ssl.SSLError, OSError):
                continue
            if candidate.cert_store_stats().get("x509_ca"):
                log(f"  (system trust store is empty; using the CA bundle at {cafile}")
                log("   -- TLS verification stays ON)")
                ctx = candidate
                break
        else:
            log("  WARNING: no CA certificates available for stdlib TLS -- HTTPS calls")
            log("  will fail with CERTIFICATE_VERIFY_FAILED. Fix: run the")
            log("  'Install Certificates.command' in your Python folder (macOS")
            log("  python.org builds), or:  python -m pip install certifi")
    _TLS_CONTEXT = ctx
    return ctx


def err_code(exc):
    """Extract the AWS error Code from a botocore ClientError."""
    try:
        return exc.response["Error"]["Code"]
    except Exception:
        return ""


def swallow(fn, **kwargs):
    """Call an AWS op; tolerate any client error (idempotent delete helper)."""
    try:
        fn(**kwargs)
    except (ClientError, BotoCoreError) as e:
        log(f"    (skipped: {err_code(e) or e})")


def paginate(fn, **kwargs):
    """Yield all items from a paginated list_* call.

    Auto-detects the single list-valued response key (AgentCore list responses
    are not uniform: 'items', 'policyEngines', 'policies', 'agentRuntimes',
    'UserPools', ...) and follows whichever of nextToken/NextToken the service
    uses. Client errors terminate the iteration silently -- lookups treat "can't
    list" the same as "not found".
    """
    token_key, token_val = None, None
    while True:
        kw = dict(kwargs)
        if token_val:
            kw[token_key] = token_val
        try:
            resp = fn(**kw)
        except (ClientError, BotoCoreError):
            return
        for k, v in resp.items():
            if k != "ResponseMetadata" and isinstance(v, list):
                for item in v:
                    yield item
                break
        nxt, cnxt = resp.get("nextToken"), resp.get("NextToken")
        if nxt:
            token_key, token_val = "nextToken", nxt
        elif cnxt:
            token_key, token_val = "NextToken", cnxt
        else:
            return


def poll(fn, ok, fail, attempts=60, delay=5, label=""):
    """Poll fn() until it returns `ok`, a status in `fail`, or the budget ends.

    Returns True only on `ok`. Failure states and exhausted budgets are always
    announced -- a silent waiter timeout must never look like success.
    """
    for _ in range(attempts):
        try:
            st = fn()
        except (ClientError, BotoCoreError):
            st = None
        if st == ok:
            return True
        if st in fail:
            log(f"  {label} entered {st}")
            return False
        time.sleep(delay)
    log(f"  {label} did not reach {ok} within the wait budget -- continuing.")
    return False


def wait_until(pred, attempts=30, delay=5, label=""):
    """Poll pred() until truthy or the budget ends; announce a timeout."""
    for _ in range(attempts):
        try:
            if pred():
                return True
        except (ClientError, BotoCoreError):
            pass
        time.sleep(delay)
    if label:
        log(f"  WARNING: {label} not confirmed within the wait budget -- continuing.")
    return False


def make_session(region, profile=None):
    """boto3 session using the standard credential chain (env vars, profiles,
    SSO cache, instance/container roles) -- any method the AWS CLI supports
    works here too. `profile` mirrors the AWS CLI's --profile flag."""
    try:
        session = boto3.session.Session(region_name=region, profile_name=profile or None)
        if profile:
            # Resolve the profile eagerly so an unknown name fails with
            # advice here instead of a traceback at the first API call.
            session.get_credentials()
        return session
    except ProfileNotFound:
        log(f"AWS profile '{profile}' was not found in your AWS config.")
        log("List available profiles with:  aws configure list-profiles")
        raise SystemExit(1)


def agentcore_client(session, region, need_policy_apis=False):
    """Create the AgentCore control-plane client with friendly version errors."""
    try:
        client = session.client("bedrock-agentcore-control", region_name=region)
    except UnknownServiceError:
        log("boto3 predates AgentCore -- update boto3:  python3 -m pip install --upgrade boto3")
        raise SystemExit(1)
    if need_policy_apis and not hasattr(client, "create_policy_engine"):
        log("This boto3 has AgentCore but predates AgentCore Policy -- update it:")
        log("  python3 -m pip install --upgrade boto3")
        raise SystemExit(1)
    return client


def agentcore_data_client(session, region):
    """The AgentCore data-plane client (events, memory records). Separate service
    from the control plane ('bedrock-agentcore' vs 'bedrock-agentcore-control')."""
    try:
        client = session.client("bedrock-agentcore", region_name=region)
    except UnknownServiceError:
        log("boto3 predates AgentCore -- update boto3:  python3 -m pip install --upgrade boto3")
        raise SystemExit(1)
    if not hasattr(client, "create_event"):
        log("This boto3 has AgentCore but predates AgentCore Memory -- update it:")
        log("  python3 -m pip install --upgrade boto3")
        raise SystemExit(1)
    return client


def resolve_account(session, region):
    """Return the account id, or exit with credential advice."""
    sts = session.client("sts", region_name=region)
    try:
        ident = sts.get_caller_identity()
    except (ClientError, NoCredentialsError, BotoCoreError) as e:
        log(f"Could not resolve AWS credentials/identity: {e}")
        if "expired" in str(e).lower() or "token" in str(e).lower():
            log("Your session likely expired -- log in again (aws sso login "
                "--profile <name>, aws configure, aws login if your CLI has it, "
                "or your org's tool) and re-run.")
            log("Every command here is idempotent, so re-running after re-auth is safe.")
        log("Check credentials for this shell first:  aws sts get-caller-identity")
        log("(see docs/scenarios/go-live-and-operations.md#preflight, incl. the")
        log(" botocore[crt] note if you logged in via `aws login`)")
        raise SystemExit(1)
    arn = ident.get("Arn", "")
    global _warned_root
    if arn.endswith(":root") and not _warned_root:
        # Once per process -- teardown resolves identity in more than one place.
        _warned_root = True
        log("WARNING: you are running as the account ROOT user. Fine for a personal")
        log("demo tenant; for shared or production accounts use a non-root IAM user")
        log("or Identity Center role (see go-live-and-operations.md).")
    return ident["Account"]


_warned_root = False


def supports_param(client, operation, param):
    """True if the client's service model accepts `param` on `operation`.

    Used to pass `tags` to AgentCore create calls only when the installed
    botocore knows about them, so an older-but-working boto3 doesn't crash.
    """
    try:
        shape = client.meta.service_model.operation_model(operation).input_shape
        return param in shape.members
    except Exception:
        return False


def delete_role(iam, role):
    """Delete an IAM role after removing inline + detaching managed policies."""
    try:
        iam.get_role(RoleName=role)
    except (ClientError, BotoCoreError):
        log(f"[iam] role {role} not found -- skipping.")
        return
    log(f"[iam] cleaning role {role}")
    try:
        for pname in iam.list_role_policies(RoleName=role).get("PolicyNames", []):
            log(f"  [iam] deleting inline policy {pname}")
            swallow(iam.delete_role_policy, RoleName=role, PolicyName=pname)
    except (ClientError, BotoCoreError):
        pass
    try:
        for att in iam.list_attached_role_policies(RoleName=role).get("AttachedPolicies", []):
            log(f"  [iam] detaching managed policy {att['PolicyArn']}")
            swallow(iam.detach_role_policy, RoleName=role, PolicyArn=att["PolicyArn"])
    except (ClientError, BotoCoreError):
        pass
    log(f"  [iam] deleting role {role}")
    swallow(iam.delete_role, RoleName=role)
