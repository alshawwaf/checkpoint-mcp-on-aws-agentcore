"""chkpmcpaws CLI -- Check Point MCP servers on AWS Bedrock AgentCore.

The tool's job: host Check Point @chkp MCP servers as tools behind one
authenticated AgentCore gateway, and let an agent use them.

    python3 -m chkpmcpaws deploy [--servers "..."]      # the MCP tools stack
    python3 -m chkpmcpaws chat "how many hosts?"         # ask the agent
    python3 -m chkpmcpaws status                          # read-only re-check
    python3 -m chkpmcpaws doctor                          # local preflight (no changes)
    python3 -m chkpmcpaws refresh                         # restart runtimes to
                                                       # re-read the CP secret
    python3 -m chkpmcpaws destroy [--tools-only] [--yes]

Aliases (kept for compatibility, hidden from --help): `agent` -> `chat`,
`verify` -> `status`.

Optional, separate demo (NOT part of deploy): an AWS-native AgentCore Policy
enforcement point. This is AWS's own guardrail engine, shown to demonstrate the
policy decision point -- it is NOT Check Point runtime protection (that
integration is Early Access; talk to Check Point). See docs/scenarios.

    python3 -m chkpmcpaws guardrail {provision,enforce,test,verify,destroy} [--enforce]
    python3 -m chkpmcpaws status --guardrail
    python3 -m chkpmcpaws destroy [--guardrail-only]

Global options (accepted before OR after the subcommand):
  --region   AWS region (default us-east-1)
  --prefix   namespace a second stack in the same account
  --profile  named AWS profile (same as AWS_PROFILE; any credential method
             the AWS CLI supports -- SSO, assumed roles, keys -- works, since
             boto3 reads the same chain)
"""

import argparse
import os
import sys

from . import __version__
from .awsutil import log, make_session
from .config import DEFAULT_REGION, StackConfig, load_env_file, parse_servers

# Shown in `chat -h` (epilog) and when `chat` is run with no task. Ask in
# plain English -- the agent discovers the gateway's tools and picks them.
CHAT_EXAMPLES = """\
example questions (the agent chooses the tools):

  inventory & policy
    chkpmcpaws chat "how many hosts are configured, and what access layers exist?"
    chkpmcpaws chat "list the access layers and how many rules each has"
    chkpmcpaws chat "which access rules are unused (zero hits)?"
    chkpmcpaws chat "are there any Any-to-Any rules I should worry about?"

  threat prevention & HTTPS inspection
    chkpmcpaws chat "summarize the threat-prevention posture"
    chkpmcpaws chat "is HTTPS inspection enabled, and what is bypassed?"

  gateways, logs & docs
    chkpmcpaws chat "what gateways and servers are managed, and their HA state?"
    chkpmcpaws chat "show recent dropped connections from the logs"
    chkpmcpaws chat "how do I configure HTTPS inspection on a Quantum gateway?"

  cross-server
    chkpmcpaws chat "give me a security posture summary across policy, threat prevention, and HTTPS inspection"

  with memory (recall across sessions)
    chkpmcpaws chat --session soc-review "how many hosts are configured?"
    chkpmcpaws chat --session soc-review "and how many of those did we flag last time?"

Add --guardrail to route calls through the AI guardrail gateway; --model <id> to
pick a Bedrock model; --session <id> to enable AgentCore Memory (recall + save,
per --actor); --runtime agentcore to run the same loop on a hosted AgentCore
Runtime instead of locally. With placeholder credentials the tool calls reach
your estate and error -- that still proves the chain; set real creds (chkpmcpaws
creds) for real answers.
"""


def _global_options():
    """Shared options, attachable to the root parser AND every subparser so
    they work in either position (chkpmcpaws --profile x deploy / chkpmcpaws deploy
    --profile x). SUPPRESS keeps a subparser's unset default from clobbering a
    value parsed before the subcommand; main() reads them via getattr."""
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--region",
        default=argparse.SUPPRESS,
        help=f"AWS region (default {DEFAULT_REGION}; the guardrail requires a "
        "Guardrails-in-Policy region)",
    )
    common.add_argument(
        "--prefix",
        default=argparse.SUPPRESS,
        help="Namespace every resource name for a parallel stack "
        "(lowercase, digits, hyphens; max 12 chars). Default: the standard "
        "fixed names.",
    )
    common.add_argument(
        "--profile",
        default=argparse.SUPPRESS,
        help="Named AWS profile to use (like the AWS CLI's --profile; the "
        "AWS_PROFILE env var works too). Without it, the default boto3 "
        "credential chain applies -- env vars, default profile, SSO cache, "
        "instance/container role.",
    )
    common.add_argument(
        "--plain",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Disable the live terminal UI and print plain line logging "
        "(automatic when output is piped, in CI, or with NO_COLOR).",
    )
    return common


def _add_chat_args(p):
    """Arguments for `chat` (and its hidden `agent` alias) -- defined once so the
    canonical command and the deprecated alias can never drift."""
    p.add_argument(
        "task",
        nargs="?",
        default=None,
        help='Natural-language question about your estate, e.g. '
        '"how many hosts are configured?". Run `chat` with no task to see examples.',
    )
    p.add_argument(
        "--runtime",
        choices=["local", "agentcore"],
        default="local",
        help="local: run the loop in this process (field-tested). "
        "agentcore: host it on an AgentCore Runtime (live-validated).",
    )
    p.add_argument(
        "--guardrail",
        action="store_true",
        help="Route tool calls through the AI guardrail gateway (so the guardrail "
        "governs them) instead of the MCP tools gateway. With "
        "--guardrail-provider lakera this becomes an INLINE Check Point AI "
        "Guardrail screen of the prompt before any model/tool call.",
    )
    p.add_argument(
        "--guardrail-provider",
        choices=["gateway", "lakera"],
        default=None,
        help="Which guardrail engine: 'gateway' (AWS AgentCore Policy, the "
        "default --guardrail route) or 'lakera' (the Check Point AI Guardrail / "
        "Lakera Guard -- one inline API call, identical on AWS and Azure). For "
        "lakera, set LAKERA_API_KEY / LAKERA_PROJECT_ID (env or the "
        "chkp/lakera-guard secret). Also honors CHKP_GUARDRAIL_PROVIDER.",
    )
    p.add_argument(
        "--model",
        default=None,
        help="Bedrock model / inference-profile id. Default: auto-select the best "
        "model this account can actually call (Claude preferred). Cheapest: "
        "us.amazon.nova-micro-v1:0 (Bedrock has no free tier).",
    )
    p.add_argument(
        "--session",
        default=None,
        metavar="ID",
        help="Enable AgentCore Memory for this conversation id: recall relevant "
        "facts learned in earlier sessions and save this turn. Omit for the "
        "stateless (field-tested) default. First use provisions the memory.",
    )
    p.add_argument(
        "--actor",
        default=None,
        metavar="ID",
        help="Whose memory to use (default: chkp-analyst). Facts are namespaced "
        "per actor, so different analysts keep separate long-term memory.",
    )


def _add_status_args(p):
    """Arguments for `status` (and its hidden `verify` alias)."""
    p.add_argument(
        "--guardrail",
        action="store_true",
        help="Verify the AI guardrail gateway instead of the MCP tools gateway.",
    )


def _build_parser():
    common = _global_options()
    parser = argparse.ArgumentParser(
        prog="chkpmcpaws",
        parents=[common],
        description="Check Point MCP servers on AWS Bedrock AgentCore -- host "
        "them as tools, add an AI guardrail, verify, and tear down.",
    )
    parser.add_argument("--version", action="version", version=f"chkpmcpaws {__version__}")
    # required=False so a bare `chkpmcpaws` prints full help (handled in main)
    # instead of a terse argparse error.
    sub = parser.add_subparsers(
        dest="cmd",
        required=False,
        metavar="{deploy,chat,status,doctor,refresh,creds,models,bridge,guardrail,destroy}",
        parser_class=argparse.ArgumentParser,
    )

    d = sub.add_parser(
        "deploy",
        parents=[common],
        help="Deploy the MCP tools: Check Point @chkp servers behind one "
        "authenticated AgentCore gateway",
    )
    d.add_argument(
        "--servers",
        help='Space- or comma-separated @chkp server names (no "@chkp/" prefix, '
        'no "-mcp" suffix), or "all" for every gateway-deployable server. "all" '
        "excludes argos-erm, harmony-sase, workforce-ai (need real/tenant "
        "creds) and quantum-gaia (interactive-only auth); deploy any of those "
        "explicitly by name. Also honors the SERVERS env var.",
    )
    d.add_argument(
        "--creds",
        nargs="?",
        const="chkp-credentials.env",
        default=None,
        help="Write REAL credentials from this local file (default "
        "chkp-credentials.env) as each server's secret at deploy time, so "
        "runtimes boot with them -- no separate 'creds apply'. Servers absent "
        "from the file get placeholders. Values are never logged.",
    )
    d.add_argument(
        "--no-agent",
        action="store_true",
        help="Skip provisioning the hosted agent runtime (chkp_agent). By "
        "default deploy builds and hosts it so `agent --runtime agentcore` "
        "is instant from the first ask; the local agent works either way.",
    )
    d.add_argument(
        "--no-model-access",
        action="store_true",
        help="Skip auto-enabling Bedrock access to the preferred Claude models. "
        "By default deploy grants it (recording what it enabled so destroy "
        "revokes only that); use this to leave model access untouched.",
    )

    sub.add_parser(
        "refresh",
        parents=[common],
        help="Restart the MCP tool runtimes so they re-read the Secrets Manager "
        "secret -- run this after changing the Check Point credentials",
    )

    c = sub.add_parser(
        "creds",
        parents=[common],
        help="Manage Check Point credentials from a local gitignored .env file: "
        "write the per-server Secrets Manager secrets and restart runtimes",
    )
    c.add_argument(
        "action",
        choices=["template", "apply"],
        help="template (write a starter creds file for your deployed servers) | "
        "apply (write the secrets from the file + refresh runtimes)",
    )
    c.add_argument(
        "--file",
        default=None,
        help="Credentials file path (default chkp-credentials.env).",
    )

    # -- canonical `chat` / `status` (match the Azure `chkpmcpaz` surface) -----
    chat = sub.add_parser(
        "chat",
        parents=[common],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        help="Run the Check Point security-ops agent (Claude on Bedrock) through the gateway",
        epilog=CHAT_EXAMPLES,
    )
    _add_chat_args(chat)

    status = sub.add_parser(
        "status",
        parents=[common],
        help="Read-only: token + tools/list through the gateway",
    )
    _add_status_args(status)

    sub.add_parser(
        "doctor",
        parents=[common],
        help="Local preflight: python3/boto3 versions + credential/region "
        "readiness -- checks only, changes nothing",
    )  # doctor takes only the shared global options

    # -- hidden, silent deprecated aliases (kept working; omitted from --help) --
    # NOTE: argparse renders `help=SUPPRESS` literally as "==SUPPRESS==", so the
    # alias must be registered WITHOUT a `help=` kwarg to stay out of the command
    # list; it still parses identically and dispatches to the canonical handler.
    agent_alias = sub.add_parser(
        "agent",
        parents=[common],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=CHAT_EXAMPLES,
    )
    _add_chat_args(agent_alias)

    verify_alias = sub.add_parser("verify", parents=[common])
    _add_status_args(verify_alias)

    m = sub.add_parser(
        "models",
        parents=[common],
        help="Manage Bedrock access to the preferred Claude models: enable "
        "(create the agreements), status (read-only), disable (revoke only "
        "what this tool enabled). `deploy` enables by default.",
    )
    m.add_argument(
        "action",
        choices=["enable", "status", "disable"],
        help="enable (grant Claude access + record it) | status (show each "
        "model's availability) | disable (revoke only the agreements this "
        "tool created)",
    )

    b = sub.add_parser(
        "bridge",
        parents=[common],
        help="HTTPS front door for the hosted agent: a bearer-token Lambda "
        "Function URL any client can call (Teams via Power Automate, n8n, "
        "curl). AWS-aware clients like Postman can also sign SigV4 directly "
        "-- `bridge show` prints both.",
    )
    b.add_argument(
        "action",
        choices=["provision", "show", "destroy"],
        help="provision (create/refresh the endpoint + token) | show (print "
        "URL, curl example, and the direct SigV4 recipe) | destroy (remove it)",
    )
    b.add_argument(
        "--reveal-token",
        action="store_true",
        help="With show: also print the bearer token (otherwise only the "
        "Secrets Manager command to fetch it).",
    )

    g = sub.add_parser(
        "guardrail",
        parents=[common],
        help="[optional demo] AWS-native AgentCore Policy enforcement point "
        "-- NOT Check Point runtime protection (that integration is Early Access)",
        description="OPTIONAL DEMO -- separate from the MCP tools deploy. Stands up "
        "AWS's own AgentCore Policy + Bedrock Guardrails at a separate gateway to "
        "demonstrate the gateway policy decision point (deterministic allow/deny). "
        "This is NOT Check Point runtime protection: that AgentCore integration is "
        "Early Access -- contact Check Point to join. Requires a Guardrails-in-Policy region.",
    )
    g.add_argument(
        "action",
        choices=["provision", "enforce", "test", "verify", "destroy"],
        help="provision (LOG_ONLY) | enforce (provision + flip to ENFORCE) | "
        "test (benign + injection traffic, report decisions) | verify "
        "(read-only tool list through the guardrail gateway) | destroy",
    )
    g.add_argument(
        "--enforce",
        action="store_true",
        help="With 'provision': flip the guardrail gateway to ENFORCE afterwards.",
    )

    t = sub.add_parser(
        "destroy",
        parents=[common],
        help="Destroy the guardrail (if deployed) then the MCP tools, in the "
        "safe order (the guardrail target references an MCP tools runtime)",
    )
    grp = t.add_mutually_exclusive_group()
    grp.add_argument("--tools-only", action="store_true", help="Tear down only the MCP tools stack.")
    grp.add_argument("--guardrail-only", action="store_true", help="Tear down only the AI guardrail.")
    t.add_argument(
        "--force-delete-secret",
        action="store_true",
        help="Purge the secret immediately (default: 7-day recovery window).",
    )
    t.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Skip the confirmation prompt (required when not running in a terminal).",
    )
    return parser


def _confirm_destroy(args):
    if args.yes:
        return True
    if not sys.stdin.isatty():
        log("Refusing to destroy without confirmation in a non-interactive shell.")
        log("Re-run with --yes to proceed.")
        return False
    from . import ui

    prompt = "Proceed and destroy the items above? [y/N] "
    if sys.stdout.isatty():
        prompt = ui.BOLD + "Proceed and destroy the items above?" + ui.RESET + " [y/N] "
    try:
        reply = input(prompt)
    except EOFError:
        return False
    return reply.strip().lower() in ("y", "yes")


def main(argv=None):
    try:
        return _main(argv)
    except KeyboardInterrupt:
        log("\nInterrupted. Every command is idempotent -- re-run it to continue.")
        return 130
    except Exception as e:  # noqa: BLE001 -- last-resort credential guard
        # Credentials can expire MID-run (boto3 refreshes lazily on the first
        # real API call of any client), so a command that never reaches
        # resolve_account() -- or that outlives its session -- would otherwise
        # dump a raw traceback (live-observed: `models status` after an
        # `aws login` session expired -> LoginRefreshRequired from SSM).
        if not _is_credential_error(e):
            raise
        log("Your AWS session has expired or credentials are unavailable.")
        log("Log in again (aws sso login --profile <name>, aws configure, or")
        log("aws login if your CLI has it), then re-run the same command --")
        log("every command here is idempotent, so re-running is safe.")
        log(f"  ({type(e).__name__}: {str(e)[:160]})")
        return 1


def _is_credential_error(exc):
    """True for the credential-expiry/missing shapes boto3 raises lazily."""
    from botocore.exceptions import (
        BotoCoreError,
        ClientError,
        NoCredentialsError,
    )
    try:
        from botocore.exceptions import LoginError  # newer botocore (aws login)
    except ImportError:  # pragma: no cover
        LoginError = ()
    if isinstance(exc, (NoCredentialsError, LoginError)):
        return True
    if isinstance(exc, ClientError):
        code = (exc.response or {}).get("Error", {}).get("Code", "")
        return code in ("ExpiredToken", "ExpiredTokenException",
                        "RequestExpired", "InvalidClientTokenId",
                        "UnrecognizedClientException")
    if isinstance(exc, BotoCoreError):
        s = str(exc).lower()
        return "expired" in s or "credential" in s or "reauthenticate" in s
    return False


def _main(argv=None):
    # Auto-load a local .env (gitignored) so guardrail creds like LAKERA_API_KEY
    # are picked up without a manual export -- explicit env vars still win.
    load_env_file()
    parser = _build_parser()
    args = parser.parse_args(argv)

    # No subcommand -> show the full help (friendlier than argparse's terse
    # `usage: ... error: the following arguments are required: cmd`).
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0

    # Deprecated aliases dispatch to the identical handler. Normalize to the
    # canonical verb and print a quiet one-line note to STDERR (never log(),
    # which targets stdout / the full-screen UI sink) so piped output and the
    # live UI stay clean and no scary banner is raised.
    _ALIASES = {"agent": "chat", "verify": "status"}
    if args.cmd in _ALIASES:
        canonical = _ALIASES[args.cmd]
        sys.stderr.write(f"note: `{args.cmd}` is now `{canonical}`\n")
        args.cmd = canonical

    # Global options may live on the root parser or the subparser (SUPPRESS
    # defaults mean the attribute is absent when never passed).
    region = getattr(args, "region", DEFAULT_REGION)
    prefix = getattr(args, "prefix", "")
    profile = getattr(args, "profile", None)
    if getattr(args, "plain", False):
        from . import ui

        ui.FORCE_PLAIN = True

    servers = None
    if args.cmd == "deploy":
        servers = parse_servers(args.servers or os.environ.get("SERVERS") or "")
    cfg_kwargs = {"region": region, "prefix": prefix}
    if servers:
        cfg_kwargs["servers"] = servers
    cfg = StackConfig(**cfg_kwargs)
    try:
        cfg.validate()
    except ValueError as e:
        log(f"Invalid options: {e}")
        return 2

    session = make_session(cfg.region, profile=profile)

    if args.cmd == "deploy":
        from . import build

        rc = build.deploy(cfg, session, creds_file=getattr(args, "creds", None),
                          include_agent=not getattr(args, "no_agent", False),
                          enable_models=not getattr(args, "no_model_access", False))
        if rc != 0:
            log(f"\nMCP tools deploy reported failures (exit {rc}).")
            return rc
        log("\nStatus   : python3 -m chkpmcpaws status")
        log("Ask      : python3 -m chkpmcpaws chat \"how many hosts are configured?\"")
        return 0

    if args.cmd == "chat":
        if not args.task:
            log("Give the agent a question, e.g.:\n")
            log('  python3 -m chkpmcpaws chat "how many hosts are configured?"\n')
            log(CHAT_EXAMPLES)
            return 2
        from . import agent

        if getattr(args, "guardrail_provider", None):
            os.environ["CHKP_GUARDRAIL_PROVIDER"] = args.guardrail_provider
        return agent.run(cfg, session, args.task, runtime=args.runtime,
                         use_guardrail=args.guardrail, model=args.model,
                         session_id=args.session, actor=args.actor)

    if args.cmd == "refresh":
        from . import build

        return build.refresh(cfg, session)

    if args.cmd == "creds":
        from . import creds

        if args.action == "template":
            return creds.template(cfg, session, path=args.file)
        return creds.apply(cfg, session, path=args.file)

    if args.cmd == "status":
        from . import verify

        return verify.verify(cfg, session, guardrail=args.guardrail)

    if args.cmd == "doctor":
        from . import doctor

        return doctor.run_doctor(cfg, session)

    if args.cmd == "models":
        from . import models

        if args.action == "enable":
            models.enable(cfg, session)
            return 0
        if args.action == "status":
            return models.status(cfg, session)
        revoked = models.disable_enabled(cfg, session)
        log(revoked or "No model access enabled by this tool -- nothing to revoke.")
        return 0

    if args.cmd == "bridge":
        from . import bridge

        if args.action == "provision":
            return bridge.provision(cfg, session)
        if args.action == "show":
            return bridge.show(cfg, session, reveal=args.reveal_token)
        return bridge.destroy(cfg, session)

    if args.cmd == "guardrail":
        from . import guardrail

        if args.action in ("provision", "enforce"):
            enforce = args.enforce or args.action == "enforce"
            return guardrail.provision(cfg, session, enforce=enforce)
        if args.action == "test":
            return guardrail.test(cfg, session)
        if args.action == "verify":
            from . import verify

            return verify.verify(cfg, session, guardrail=True)
        return guardrail.destroy(cfg, session)

    if args.cmd == "destroy":
        from . import destroy as destroy_mod, guardrail, ui
        from .awsutil import agentcore_client, resolve_account

        # Inventory + confirmation run in PLAIN text first: a y/N prompt can't
        # live inside a full-screen (alt-screen) takeover. The actual deletion
        # then runs under the same live progress UI as deploy.
        agentcore = agentcore_client(session, cfg.region)
        account_id = resolve_account(session, cfg.region)
        inv_g = [] if args.tools_only else guardrail.inventory(cfg, session, agentcore)
        inv_t = [] if args.guardrail_only else destroy_mod.inventory(cfg, session, agentcore, account_id)

        scope = f"region {cfg.region}" + (f", prefix '{cfg.prefix}'" if cfg.prefix else "")
        if not inv_t and not inv_g:
            log(f"Nothing from this stack found ({scope}) -- nothing to destroy.")
            return 0
        sections = ([("AI guardrail", inv_g)] if inv_g else []) + \
                   ([("MCP tools", inv_t)] if inv_t else [])
        notes = []
        if cfg.prefix:
            notes.append(f"stack prefix: {cfg.prefix}")
        if not args.tools_only and not inv_g:
            notes.append("AI guardrail: not deployed — will be skipped")
        if not args.force_delete_secret and inv_t:
            notes.append("secret keeps a 7-day recovery window (--force-delete-secret to purge)")
        ui.render_destroy_plan(cfg.region, sections, notes)
        if not _confirm_destroy(args):
            return 1

        steps = ([f"Destroy AI guardrail ({len(inv_g)} resources)"] if inv_g else []) + \
                ([f"Destroy MCP tools ({len(inv_t)} resources)"] if inv_t else [])
        rep = ui.Reporter("destroy", "DESTROY", steps, cfg.region)
        rep.set_context(f"acct {account_id} · {cfg.region}")
        ui.activate(rep)
        rc_g = rc_t = 0
        try:
            if inv_g:
                rep.begin()  # Destroy AI guardrail (first: target references an MCP tools runtime)
                rc_g = guardrail.destroy(cfg, session)
            if inv_t:
                rep.begin()  # Destroy MCP tools
                rc_t = destroy_mod.destroy_mcp_tools(
                    cfg, session, force_delete_secret=args.force_delete_secret
                )
        except BaseException:
            rep.fail_current()
            ui.deactivate()
            rep.close(ok=False, summary=["Destroy aborted -- idempotent, safe to re-run. See the log file."])
            raise
        ui.deactivate()
        ok = not (rc_g or rc_t)
        summary = [ui.done_banner("DESTROYED", ok=ok) + f"  ·  {cfg.region}"]
        if inv_g:
            summary.append(f"  AI guardrail : {'removed' if not rc_g else 'INCOMPLETE (re-run)'}")
        if inv_t:
            summary.append(f"  MCP tools    : {'removed' if not rc_t else 'INCOMPLETE (re-run)'}")
        if not args.force_delete_secret and inv_t:
            summary.append("  Secret       : scheduled for deletion (7-day recovery window)")
        if not ok:
            summary.append("  Both halves are idempotent -- re-run destroy to finish.")
        rep.close(ok=ok, summary=summary)
        return 0 if ok else 1

    return 2  # unreachable: argparse enforces the choices


if __name__ == "__main__":
    sys.exit(main())
