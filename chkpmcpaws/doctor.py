"""Local preflight (`chkpmcpaws doctor`): check the tools and credentials this
stack needs BEFORE any mutation. Checks only -- creates and changes nothing.

Hard FAILURES (exit 1) are things a deploy cannot survive: python < 3.9, boto3
missing or too old to know the AgentCore service model, and AWS credentials
that don't resolve. WARNINGS are things a deploy tolerates: running as account
root, the optional `mcp` extra absent, an empty stdlib TLS trust store, a region
outside the OPTIONAL guardrail demo's supported set, and a boto3 that predates
the OPTIONAL AgentCore Memory / Policy features.

Unlike the Azure port there is deliberately NO node/npx or docker hard-fail: on
AWS the @chkp MCP servers run as remote containers on AgentCore Runtime and the
agent image builds remotely on CodeBuild, so neither Node nor Docker (nor even
the `aws` CLI binary) is ever required on the operator's box. They appear only
as an informational note.

A failed `sts get-caller-identity` is reported as a CHECK FAILURE with re-auth
advice rather than raised: doctor's whole job is diagnosis, so it must finish
its report even when the session is expired.
"""

import ssl
import sys

from . import __version__
from .awsutil import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    UnknownServiceError,
    _ca_bundle_candidates,
    log,
)
from .config import GUARDRAILS_REGIONS
from .mcpcheck import mcp_available

MIN_PYTHON = (3, 9)
MIN_BOTO3_HINT = "1.39.9"  # first release carrying the AgentCore service model

OK, WARN, FAIL = "ok", "warn", "fail"
_GLYPH = {OK: "✓", WARN: "⚠", FAIL: "✗"}


def _say(status, label, detail=""):
    line = f"  {_GLYPH[status]} {label}"
    if detail:
        line += f" -- {detail}"
    log(line)
    return status


def run_doctor(cfg, session):
    """Run every local, read-only check; return 0 when no HARD failure was
    found, 1 otherwise. Never mutates AWS and never raises."""
    results = []
    log(f"chkpmcpaws doctor {__version__} -- local preflight "
        "(nothing is created or changed)\n")

    # -- python ---------------------------------------------------------------
    py = sys.version_info
    if py >= MIN_PYTHON:
        results.append(_say(OK, f"python {py.major}.{py.minor}.{py.micro}",
                            f">= {'.'.join(map(str, MIN_PYTHON))} required"))
    else:
        results.append(_say(FAIL, f"python {py.major}.{py.minor}.{py.micro}",
                            f"{'.'.join(map(str, MIN_PYTHON))}+ required -- "
                            "upgrade and re-run with python3"))

    # -- boto3 (the only hard dependency) -------------------------------------
    try:
        import boto3
        results.append(_say(OK, f"boto3 {boto3.__version__}",
                            "the tool's only hard dependency"))
    except ImportError:  # pragma: no cover -- awsutil already exits if absent
        results.append(_say(FAIL, "boto3 not installed",
                            "install: python3 -m pip install boto3"))

    # -- boto3 recent enough for AgentCore ------------------------------------
    # session.client(...) only builds from the local service model (no network),
    # so this stays read-only. An old boto3 raises UnknownServiceError.
    control = None
    try:
        control = session.client("bedrock-agentcore-control", region_name=cfg.region)
        results.append(_say(OK, "boto3 knows AgentCore",
                            "bedrock-agentcore-control service model present"))
    except UnknownServiceError:
        results.append(_say(FAIL, "boto3 too old for AgentCore",
                            "this boto3 predates the bedrock-agentcore-control "
                            f"service -- upgrade: python3 -m pip install --upgrade "
                            f"boto3 (>= {MIN_BOTO3_HINT})"))

    # -- AWS identity via the boto3 credential chain (no `aws` binary needed) --
    arn = None
    try:
        sts = session.client("sts", region_name=cfg.region)
        ident = sts.get_caller_identity()
        arn = ident.get("Arn", "")
        results.append(_say(OK, "AWS identity",
                            f"account {ident.get('Account')} ({arn})"))
    except (ClientError, NoCredentialsError, BotoCoreError) as e:
        results.append(_say(FAIL, "AWS credentials",
                            f"sts get-caller-identity failed ({str(e)[:120]}) -- "
                            "log in again (aws sso login --profile <name>, aws "
                            "configure, or aws login), then re-run"))

    # -- identity is not the account root user (WARN) -------------------------
    if arn and arn.endswith(":root"):
        results.append(_say(WARN, "AWS identity is account ROOT",
                            "fine for a personal demo tenant; use a non-root IAM "
                            "user or Identity Center role for shared/production "
                            "accounts"))
    elif arn:
        results.append(_say(OK, "AWS identity is a non-root principal",
                            "good"))

    # -- optional `mcp` extra (WARN) ------------------------------------------
    if mcp_available():
        results.append(_say(OK, "mcp extra importable",
                            "local `chat` + full paginated `status` tools/list"))
    else:
        results.append(_say(WARN, "mcp extra not installed",
                            "needed for `chat --runtime local` and the full "
                            "`status` tools/list (a stdlib first-page listing is "
                            'used otherwise) -- install: pip install "chkpmcpaws[mcp]"'))

    # -- stdlib TLS trust store (WARN) ----------------------------------------
    try:
        has_ca = bool(ssl.create_default_context().cert_store_stats().get("x509_ca"))
    except Exception:  # noqa: BLE001 -- probing must never crash doctor
        has_ca = False
    if has_ca:
        results.append(_say(OK, "TLS trust store",
                            "system CA store populated -- stdlib HTTPS verification on"))
    else:
        bundle = next(iter(_ca_bundle_candidates()), None)
        if bundle:
            results.append(_say(WARN, "TLS trust store",
                                f"system store empty -- falling back to the CA bundle "
                                f"at {bundle} (verification stays ON)"))
        else:
            results.append(_say(WARN, "TLS trust store",
                                "system store empty and no certifi/botocore CA bundle "
                                "found -- stdlib HTTPS may fail with "
                                "CERTIFICATE_VERIFY_FAILED. Fix: run 'Install "
                                "Certificates.command' (macOS python.org builds) or "
                                "python3 -m pip install certifi"))

    # -- region: no hard gate; only the OPTIONAL guardrail demo needs one ------
    if cfg.region in GUARDRAILS_REGIONS:
        results.append(_say(OK, f"region {cfg.region}",
                            "core deploy has no region gate; this region also "
                            "supports the optional AI guardrail demo"))
    else:
        results.append(_say(WARN, f"region {cfg.region}",
                            "core MCP tools deploy has no region gate, but the "
                            "OPTIONAL guardrail demo needs one of: "
                            + ", ".join(sorted(GUARDRAILS_REGIONS))))

    # -- optional AgentCore Policy / Memory service models (WARN) -------------
    if control is not None:
        if hasattr(control, "create_policy_engine"):
            results.append(_say(OK, "AgentCore Policy APIs",
                                "present (only the optional guardrail demo needs them)"))
        else:
            results.append(_say(WARN, "AgentCore Policy APIs",
                                "this boto3 has AgentCore but predates AgentCore "
                                "Policy -- only the optional guardrail demo needs "
                                "them; upgrade boto3 to use it"))
    try:
        data = session.client("bedrock-agentcore", region_name=cfg.region)
        if hasattr(data, "create_event"):
            results.append(_say(OK, "AgentCore Memory APIs",
                                "present (only `chat --session` recall needs them)"))
        else:
            results.append(_say(WARN, "AgentCore Memory APIs",
                                "this boto3 predates AgentCore Memory -- only "
                                "`chat --session` recall needs it; upgrade boto3 "
                                "to use it"))
    except UnknownServiceError:
        pass  # already reported by the AgentCore hard-fail above

    # -- informational: what is NOT needed locally ----------------------------
    log("\nnot required on your machine (they run remotely):")
    log("  * node / npx -- the @chkp MCP servers run as containers on AgentCore Runtime")
    log("  * docker -- the agent image builds remotely on AWS CodeBuild")
    log("  * the aws CLI binary -- boto3 uses the same credential chain directly")
    log("  Bedrock model access is auto-enabled by `deploy`; confirm it any time with")
    log("    python3 -m chkpmcpaws models status")

    # -- org policy reminders -------------------------------------------------
    log("\norg policy reminders:")
    log("  * secrets live in AWS Secrets Manager only -- never in code, env files")
    log("    you commit, or command lines (chkp-credentials.env is gitignored)")
    log("  * TLS verification is always on; this tool never disables it")
    log("  * every gateway is Cognito-JWT authenticated; there is no anonymous surface")

    fails = sum(1 for r in results if r == FAIL)
    warns = sum(1 for r in results if r == WARN)
    if fails:
        log(f"\ndoctor: {fails} check(s) FAILED, {warns} warning(s) -- fix the "
            "failures above before deploying.")
        return 1
    log(f"\ndoctor: all checks passed ({warns} warning(s)). Ready to deploy:")
    log("  python3 -m chkpmcpaws deploy")
    return 0
