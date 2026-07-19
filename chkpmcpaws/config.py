"""Single source of truth for region, server set, and every resource name.

With no --prefix the derived names are EXACTLY the legacy, field-tested names
the original scripts used, so existing deployments stay discoverable and
teardown-able. A --prefix derives namespaced variants for a parallel stack in
the same account/region (note: target names change, so tool namespaces like
`quantummanagement___show_hosts` gain the prefix too).
"""

import os
import re
from dataclasses import dataclass

DEFAULT_REGION = "us-east-1"

# --- Guardrail engine selection -------------------------------------------
# Which engine screens prompts: the AWS-native AgentCore-Policy gateway
# (default) or the Check Point AI Guardrail (Lakera Guard) -- one inline POST to
# the Guard API, identical on AWS and Azure. Selected by CHKP_GUARDRAIL_PROVIDER;
# the Lakera key/project come from LAKERA_API_KEY / LAKERA_PROJECT_ID (the
# environment, or the chkp/lakera-guard Secrets Manager secret).
ENV_GUARDRAIL_PROVIDER = "CHKP_GUARDRAIL_PROVIDER"
ENV_LAKERA_API_KEY = "LAKERA_API_KEY"
ENV_LAKERA_PROJECT_ID = "LAKERA_PROJECT_ID"
ENV_LAKERA_API_URL = "LAKERA_API_URL"
# Accepted fallbacks for the canonical names above (an earlier naming). Reading
# both means an operator's existing LAKERA_GUARD_* values keep working.
ENV_LAKERA_API_KEY_ALIASES = ("LAKERA_GUARD_API_KEY",)
ENV_LAKERA_PROJECT_ID_ALIASES = ("LAKERA_GUARD_PROJECT_ID",)
ENV_LAKERA_API_URL_ALIASES = ("LAKERA_GUARD_URL", "LAKERA_GUARD_API_URL")
LAKERA_DEFAULT_URL = "https://api.lakera.ai/v2/guard"
GUARDRAIL_PROVIDER_GATEWAY = "gateway"
GUARDRAIL_PROVIDER_LAKERA = "lakera"
DEFAULT_GUARDRAIL_PROVIDER = GUARDRAIL_PROVIDER_GATEWAY

DEFAULT_ENV_FILE = ".env"


def resolve_guardrail_provider(value):
    """Map CHKP_GUARDRAIL_PROVIDER to a provider. 'lakera' (and Check Point
    aliases) -> the Check Point AI Guardrail; anything else -> the AWS-native
    AgentCore-Policy gateway default. Pure/unit-tested."""
    v = (value or "").strip().lower()
    if v in ("lakera", "ai-guardrail", "aiguardrail", "checkpoint", "chkp", "cp"):
        return GUARDRAIL_PROVIDER_LAKERA
    return DEFAULT_GUARDRAIL_PROVIDER


def lakera_env(env):
    """(api_key, project_id, url) read from an env mapping, accepting the
    LAKERA_GUARD_* alias names as fallbacks for the canonical LAKERA_* names.
    Empty/absent -> "" for the key and None for project id/url. Values are never
    logged. Pure/unit-tested."""
    def pick(canonical, aliases):
        for name in (canonical, *aliases):
            v = env.get(name)
            if v:
                return v
        return None
    return (
        pick(ENV_LAKERA_API_KEY, ENV_LAKERA_API_KEY_ALIASES) or "",
        pick(ENV_LAKERA_PROJECT_ID, ENV_LAKERA_PROJECT_ID_ALIASES),
        pick(ENV_LAKERA_API_URL, ENV_LAKERA_API_URL_ALIASES),
    )


def load_env_file(path=DEFAULT_ENV_FILE):
    """Load KEY=VALUE lines from a local .env into os.environ so `chat`/`deploy`
    pick up e.g. LAKERA_API_KEY without a manual `export`. Dependency-free; a
    no-op when the file is absent. Uses setdefault semantics -- an
    already-exported variable ALWAYS wins over the file (explicit > implicit).
    Skips blanks, `#` comments, and `[section]` headers (those belong in
    chkp-credentials.env, not here); drops an optional leading `export ` and one
    layer of matching surrounding quotes; NO variable interpolation (values may
    contain $/%/=). Returns the list of key NAMES set (values never logged)."""
    try:
        # utf-8-sig so a leading UTF-8 BOM (Windows editors) is stripped rather
        # than corrupting the first line's key name.
        with open(path, encoding="utf-8-sig") as fh:
            lines = fh.readlines()
    except OSError:
        return []
    loaded = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        if not key:
            continue
        val = val.strip()
        if val[:1] in ("'", '"'):          # quoted: literal between the quotes
            end = val.find(val[0], 1)
            val = val[1:end] if end != -1 else val[1:]
        else:                              # unquoted: a ' #' / '\t#' starts a comment
            cuts = [i for i in (val.find(" #"), val.find("\t#")) if i != -1]
            if cuts:
                val = val[:min(cuts)].rstrip()
        if key not in os.environ:
            os.environ[key] = val
            loaded.append(key)
    return loaded


# The @chkp MCP servers we host (15 of the 18 in the upstream repo). `creds`
# names the SERVER-SIDE credential SHAPE (env vars wired into the container's
# secret), or None if the server has no server-side secret -- it may still
# carry an agent-side secret (see agent_creds, quantum-gaia). Secrets are
# ALWAYS PER-SERVER: every credentialed server gets its own
# chkp/<server> secret, so two servers can point at DIFFERENT Check Point
# systems even when their credentials look alike (no shared "groups").
# `version` is the latest published tag as of 2026-07-15 (reference/pinning).
SERVER_CATALOG = {
    # -- Management-shaped: same env vars, but each gets its OWN secret -------
    "quantum-management": {"creds": "management", "version": "1.4.7"},
    "management-logs":    {"creds": "management", "version": "1.4.6"},
    "threat-prevention":  {"creds": "management", "version": "1.5.4"},
    "https-inspection":   {"creds": "management", "version": "1.4.6"},
    "policy-insights":    {"creds": "management", "version": "0.3.5"},
    "quantum-gw-cli":     {"creds": "management", "version": "1.4.8"},
    # -- Product-specific credentials, own secret each -----------------------
    "reputation-service": {"creds": "reputation-service", "version": "1.3.1"},
    "threat-emulation":   {"creds": "threat-emulation", "version": "1.3.1"},
    "cloudguard-waf":     {"creds": "cloudguard-waf", "version": "0.1.0"},
    # argos-erm can't enumerate tools without real Argos creds, so its gateway
    # target FAILS ("missing tools capability") on placeholders -- excluded from
    # `--servers all` for now (still deployable explicitly to troubleshoot).
    "argos-erm":          {"creds": "argos-erm", "version": "0.5.4",
                           "exclude_from_all": True,
                           "note": "needs real Argos creds to list tools (excluded from 'all')"},
    "spark-management":   {"creds": "spark-management", "version": "1.4.8"},
    # harmony-sase + workforce-ai were added from the upstream repo catalog.
    # Both need tenant-specific API credentials and are NOT yet validated on
    # this stack, so they are excluded from `--servers all` (deployable by
    # name once you have a tenant + keys).
    "harmony-sase":       {"creds": "harmony-sase", "version": "1.3.1",
                           "exclude_from_all": True,
                           "note": "Harmony SASE API key + management host/origin (validate on your tenant)"},
    "workforce-ai":       {"creds": "workforce-ai", "version": "1.1.0",
                           "exclude_from_all": True,
                           "note": "CloudInfra API key (client id + access key + gateway URL)"},
    # quantum-gaia's ONLY credential path is interactive MCP elicitation (the
    # published server reads no env creds and takes no cred tool-args -- it
    # prompts the CLIENT for user+password mid-call). VALIDATED 2026-07-16: the
    # AgentCore Gateway does NOT relay elicitation to the connecting client, so a
    # Gaia tool call HANGS through our gateway -- it can't authenticate here.
    # Excluded from the default set for that reason (its 42 tools list, but
    # calls block). Still deployable by name; usable only in a direct-server
    # topology (e.g. Claude Desktop over stdio), where our agent-side answerer
    # (chkpmcpaws.gaia, agent_creds="gaia") fills the prompt. See invoke-from-anywhere.
    "quantum-gaia":       {"creds": None, "agent_creds": "gaia", "version": "1.3.5",
                           "exclude_from_all": True,
                           "note": "interactive-only auth; can't authenticate through the AgentCore Gateway (excluded from default + 'all')"},
    # documentation needs an Infinity Portal API key (CLIENT_ID + SECRET_KEY)
    # AND --region (EU/US/STG/LOCAL) to start -- the region is set automatically.
    "documentation":      {"creds": "documentation", "version": "1.4.6",
                           "args": "--region US",
                           "note": "Infinity Portal API key + --region (set automatically)"},
}

# Placeholder secret body per credential SHAPE (env-var key names from each
# package's README). Written at deploy so a runtime starts and fails auth
# cleanly until real creds are applied (chkpmcpaws creds apply). Never a real
# credential. Management-shaped servers reuse the same field NAMES here but
# still get SEPARATE per-server secrets.
CRED_SHAPE = {
    "management": {"MANAGEMENT_HOST": "127.0.0.1", "MANAGEMENT_PORT": "443",
                   "API_KEY": "PLACEHOLDER_NOT_A_REAL_KEY"},
    "reputation-service": {"API_KEY": "PLACEHOLDER_NOT_A_REAL_KEY"},
    "threat-emulation": {"API_KEY": "PLACEHOLDER_NOT_A_REAL_KEY"},
    "cloudguard-waf": {"WAF_CLIENT_ID": "PLACEHOLDER", "WAF_ACCESS_KEY": "PLACEHOLDER",
                       "WAF_REGION": "eu-west-1"},
    "argos-erm": {"ARGOS_API_KEY": "PLACEHOLDER", "ARGOS_CUSTOMER_ID": "PLACEHOLDER"},
    "spark-management": {"CLIENT_ID": "PLACEHOLDER", "SECRET_KEY": "PLACEHOLDER",
                         "INFINITY_PORTAL_URL": "https://portal.checkpoint.com"},
    "harmony-sase": {"API_KEY": "PLACEHOLDER_NOT_A_REAL_KEY",
                     "MANAGEMENT_HOST": "https://api.your-management-host.com/api",
                     "ORIGIN": "https://your.origin-domain.com"},
    "workforce-ai": {"CP_CI_CLIENT_ID": "PLACEHOLDER", "CP_CI_ACCESS_KEY": "PLACEHOLDER",
                     "CP_CI_GATEWAY": "https://cloudinfra-gw-us.portal.checkpoint.com"},
    # documentation authenticates to the Check Point Documentation service with
    # an Infinity Portal API key (CLIENT_ID + SECRET_KEY); --region picks the portal.
    "documentation": {"CLIENT_ID": "PLACEHOLDER", "SECRET_KEY": "PLACEHOLDER"},
    # Agent-side only: the fields our agent uses to answer the Gaia server's
    # login elicitation. Written to chkp/quantum-gaia, read by the AGENT (not
    # the gaia container). GAIA_PORT is the Gaia REST port (usually 443).
    "gaia": {"GAIA_GATEWAY_IP": "REPLACE_WITH_GATEWAY_IP", "GAIA_PORT": "443",
             "GAIA_USER": "admin", "GAIA_PASSWORD": "PLACEHOLDER"},
}

# Default deploy = 9 servers whose tools actually WORK through the gateway: the
# six management-shaped servers, the ThreatCloud pair (reputation-service,
# threat-emulation), and documentation (Infinity Portal API key). Left out of
# the default: cloudguard-waf / spark-management / harmony-sase / workforce-ai
# (tenant-specific creds), argos-erm (target won't come READY on placeholders),
# and quantum-gaia (interactive-only auth the gateway can't relay -- its tools
# list but calls hang). Every catalog server is selectable with --servers.
DEFAULT_SERVERS = ("quantum-management", "management-logs", "threat-prevention",
                   "https-inspection", "policy-insights", "quantum-gw-cli",
                   "reputation-service", "threat-emulation", "documentation")
# Bedrock Guardrails-in-Policy GA regions (checked before any guardrail action).
GUARDRAILS_REGIONS = {
    "us-east-1",
    "eu-west-2",
    "eu-north-1",
    "ap-southeast-2",
    "ap-northeast-1",
}
PROJECT_TAG = "chkp-mcp-agentcore"

_PREFIX_RE = re.compile(r"^[a-z][a-z0-9-]{0,11}$")


def parse_servers(text):
    """Split a space- or comma-separated server list into a tuple.

    The literal `all` expands to the deployable catalog -- every @chkp server
    except those flagged `exclude_from_all` (known not to reach READY on
    placeholders, e.g. argos-erm). Excluded servers stay explicitly deployable
    by name."""
    if not text:
        return ()
    if text.strip().lower() == "all":
        return tuple(s for s, m in SERVER_CATALOG.items() if not m.get("exclude_from_all"))
    return tuple(text.replace(",", " ").split())


@dataclass(frozen=True)
class StackConfig:
    region: str = DEFAULT_REGION
    prefix: str = ""  # "" -> legacy fixed names
    servers: tuple = DEFAULT_SERVERS

    def validate(self):
        if self.prefix and not _PREFIX_RE.match(self.prefix):
            raise ValueError(
                "--prefix must match [a-z][a-z0-9-]{0,11} (lowercase, digits, "
                "hyphens; max 12 chars) so every derived resource name stays legal"
            )
        if not self.servers:
            raise ValueError("no servers selected")
        unknown = [s for s in self.servers if s not in SERVER_CATALOG]
        if unknown:
            raise ValueError(
                "unknown server(s): " + ", ".join(unknown)
                + ". Known servers: " + ", ".join(sorted(SERVER_CATALOG))
            )

    # -- per-server credentials ----------------------------------------------
    def server_needs_creds(self, server):
        """True if the server stores an env-var secret (False = none/interactive)."""
        return SERVER_CATALOG.get(server, {}).get("creds") is not None

    def secret_name(self, server):
        """This server's OWN Secrets Manager secret name (chkp/<server>,
        prefix-aware). Every credentialed server gets a separate secret."""
        return self._dash(f"chkp/{server}")

    def lakera_secret_name(self):
        """Secrets Manager secret holding the Check Point AI Guardrail (Lakera)
        key + project id (chkp/lakera-guard, prefix-aware). Stack-level, not
        per-server -- the guardrail screens the agent's prompt."""
        return self._dash("chkp/lakera-guard")

    def placeholder_for(self, server):
        """Placeholder secret body (env-var keys) for the server, or {}. Covers
        BOTH server-side creds and agent-side creds (e.g. quantum-gaia's
        elicitation answers) so the creds template shows every server's fields."""
        entry = SERVER_CATALOG.get(server, {})
        shape = entry.get("creds") or entry.get("agent_creds")
        return dict(CRED_SHAPE.get(shape, {})) if shape else {}

    def agent_creds_shape(self, server):
        """The agent-side credential shape for a server (creds the AGENT uses,
        not the container), or None. Today only quantum-gaia -> 'gaia'."""
        return SERVER_CATALOG.get(server, {}).get("agent_creds")

    def server_has_secret(self, server):
        """True if this server has a stored secret of ANY kind -- server-side
        (wired to the container) or agent-side (read by the agent)."""
        entry = SERVER_CATALOG.get(server, {})
        return bool(entry.get("creds") or entry.get("agent_creds"))

    def startup_args(self, server):
        """Extra CLI flags the server's package needs at start (e.g.
        documentation-mcp's --region), passed to the container via CHKP_ARGS."""
        return SERVER_CATALOG.get(server, {}).get("args", "")

    def pkg_spec(self, server):
        """The npm package spec the runtime runs, PINNED to the catalog version
        so a deploy is reproducible (`npx -y @chkp/<server>-mcp@<version>`).
        Without a pin, npx would pull whatever is latest at deploy time, so an
        upstream release could change tool behavior under a running demo. Falls
        back to the unpinned name if a catalog entry has no version."""
        version = SERVER_CATALOG.get(server, {}).get("version")
        base = f"@chkp/{server}-mcp"
        return f"{base}@{version}" if version else base

    def servers_with_creds(self, servers):
        """Ordered subset of `servers` that need a stored secret -- server-side
        OR agent-side (so the creds template/apply covers quantum-gaia too)."""
        return [s for s in servers if self.server_has_secret(s)]

    def all_secret_names(self):
        """Every per-server secret name this stack could have created -- used by
        destroy, which doesn't know which servers were deployed. Includes
        agent-side secrets (chkp/quantum-gaia)."""
        return [self.secret_name(s) for s in SERVER_CATALOG if self.server_has_secret(s)]

    # -- internal helpers ---------------------------------------------------
    def _dash(self, base):
        return f"{base}-{self.prefix}" if self.prefix else base

    @property
    def _us(self):
        return self.prefix.replace("-", "_")

    # -- shared / MCP tools names ---------------------------------------------
    @property
    def ecr_repo(self):
        return self._dash("bedrock-agentcore-chkpmcp")

    @property
    def rt_role(self):
        return self._dash("AgentCoreRuntimeChkpMcp")

    @property
    def gw_role(self):
        return self._dash("AgentCoreGatewayRole")

    @property
    def cb_role(self):
        return self._dash("ChkpMcpCodeBuild")

    @property
    def cb_project(self):
        return self._dash("chkp-mcp-build")

    @property
    def gateway_name(self):
        return self._dash("chkp-mcp-gw")

    @property
    def pool_name(self):
        return self._dash("gateway-user-pool")

    @property
    def app_client_name(self):
        return self._dash("gateway-client")

    @property
    def res_server(self):
        return self._dash("gateway-resource-server")

    def src_bucket(self, account_id):
        return self._dash(f"chkp-mcp-src-{account_id}")

    def cognito_domain(self, account_id):
        return self._dash(f"chkp-mcp-gw-{account_id}")

    def image_uri(self, account_id):
        return f"{account_id}.dkr.ecr.{self.region}.amazonaws.com/{self.ecr_repo}:v1"

    @property
    def runtime_scan_prefix(self):
        """Every runtime this stack creates starts with this string."""
        return f"{self._us}_chkp_" if self.prefix else "chkp_"

    def runtime_name(self, server):
        return self.runtime_scan_prefix + server.replace("-", "_")

    def target_name(self, server):
        # Target name namespaces the tools: <target>___<tool>.
        base = server.replace("-", "")
        return (self.prefix.replace("-", "") + base) if self.prefix else base

    # -- AgentCore-hosted agent (opt-in; see chkpmcpaws.hosting) ----------------
    @property
    def agent_runtime_name(self):
        # Starts with runtime_scan_prefix so the existing teardown scan removes
        # it alongside the MCP-server runtimes -- no separate delete needed.
        return self.runtime_scan_prefix + "agent"

    @property
    def agent_ecr_repo(self):
        return self._dash("bedrock-agentcore-chkpmcp-agent")

    @property
    def agent_role(self):
        return self._dash("AgentCoreAgentChkp")

    def agent_image_uri(self, account_id):
        return f"{account_id}.dkr.ecr.{self.region}.amazonaws.com/{self.agent_ecr_repo}:v1"

    # -- HTTPS bridge for the hosted agent (opt-in; see chkpmcpaws.bridge) -------
    @property
    def bridge_fn(self):
        return self._dash("chkp-agent-bridge")

    @property
    def bridge_role(self):
        return self._dash("AgentBridgeChkp")

    @property
    def bridge_secret(self):
        base = "chkp/agent-bridge"
        return f"{base}-{self.prefix}" if self.prefix else base

    @property
    def model_access_param(self):
        """SSM parameter that records which Bedrock model agreements THIS stack
        created, so destroy revokes only those (never pre-existing access)."""
        return self._dash("/chkp/model-access")

    # -- AgentCore Memory names (opt-in; see chkpmcpaws.memory) ------------------
    @property
    def memory_name(self):
        # AgentCore Memory names must match [a-zA-Z][a-zA-Z0-9_]{0,47}
        # -- underscores only, no hyphens (unlike the other resources).
        return f"chkp_mcp_memory_{self._us}" if self.prefix else "chkp_mcp_memory"

    @property
    def memory_role(self):
        # Execution role AgentCore assumes to run long-term extraction.
        return self._dash("AgentCoreMemoryChkp")

    # -- AI guardrail names ---------------------------------------------
    @property
    def engine_name(self):
        return f"{self._us}_chkp_guardrail_engine" if self.prefix else "chkp_guardrail_engine"

    @property
    def permit_policy(self):
        return (
            f"{self._us}_chkp_guardrail_baseline_permit"
            if self.prefix
            else "chkp_guardrail_baseline_permit"
        )

    @property
    def guardrail_policy(self):
        return (
            f"{self._us}_chkp_guardrail_block_prompt_injection"
            if self.prefix
            else "chkp_guardrail_block_prompt_injection"
        )

    @property
    def guardrail_gateway_name(self):
        return self._dash("chkp-mcp-gw-guardrail")

    @property
    def guardrail_target(self):
        return (self.prefix.replace("-", "") + "guardrailtarget") if self.prefix else "guardrailtarget"

    @property
    def guardrail_role(self):
        return self._dash("AgentCoreGatewayRoleGuardrail")

    # -- tags -----------------------------------------------------------------
    def tags(self):
        """Audit/cost tags applied wherever the create API supports them."""
        return {"project": PROJECT_TAG, "stack": self.prefix or "default"}

    def tags_kv(self, key="Key", value="Value"):
        """Same tags as a list of {Key: ..., Value: ...} (IAM/ECR/Secrets/S3
        style); pass key='key', value='value' for CodeBuild."""
        return [{key: k, value: v} for k, v in self.tags().items()]


# --------------------------------------------------------------------------
# AWS Console links -- clickable URLs printed after deploy / in verify.
# --------------------------------------------------------------------------
def console_links(cfg, account_id=None, gateway_id=None, pool_id=None,
                  include_agent=True):
    """Clickable AWS Console links for the deployed stack (terminals
    auto-linkify full URLs). Pure and forgiving: a link that needs an id we
    do not have (account, gateway, pool) is skipped or falls back to the
    service list page, so partial/older stacks still get whatever can be
    built. Returns (label, url) pairs, the umbrella everything-by-tag link
    first; [] when there is no region to point the console at.

    Caveats: the AgentCore/CloudWatch '#...' hash fragments are
    console-internal routes and may drift -- the '?region=' base always
    lands on the right service. The Secrets Manager 'search=' filter is
    best-effort (the bare list page is the fallback behind the same URL).
    URLs assume the commercial partition (console.aws.amazon.com). The URLs
    carry only resource NAMES/ids -- never credential values."""
    region = getattr(cfg, "region", None) if cfg else None
    if not region:
        return []
    base = f"https://{region}.console.aws.amazon.com"
    # Mirror cfg.tags(): the stack tag distinguishes parallel --prefix stacks
    # in the same account/region, so THIS stack's summary links only to THIS
    # stack's resources (project tag alone would list every chkp stack).
    stack_tag = getattr(cfg, "prefix", "") or "default"
    links = [
        # Umbrella: everything the deploy tagged project=chkp-mcp-agentcore
        # AND stack=<this stack>.
        ("Everything, by tag (Tag Editor)",
         f"{base}/resource-groups/tag-editor/find-resources?region={region}"
         f"#query=regions:!%28{region}%29,"
         "resourceTypes:!%28%27AWS::AllSupported%27%29,"
         f"tagFilters:!%28%28key:project,values:!%28{PROJECT_TAG}%29%29,"
         f"%28key:stack,values:!%28{stack_tag}%29%29%29,"
         "type:TAG_EDITOR_1_0"),
        ("AgentCore runtimes (MCP servers + hosted agent)",
         f"{base}/bedrock-agentcore/home?region={region}#/agents"),
        # Deep-link the gateway when its id is known; list page otherwise.
        ("AgentCore gateway" if gateway_id else "AgentCore gateways",
         f"{base}/bedrock-agentcore/home?region={region}#/gateways"
         + (f"/{gateway_id}" if gateway_id else "")),
        ("Secrets Manager (Check Point credential secrets)",
         f"{base}/secretsmanager/listsecrets?region={region}&search=chkp%2F"),
        ("CloudWatch logs (runtime log groups)",
         f"{base}/cloudwatch/home?region={region}#logsV2:log-groups"
         "$3FlogGroupNameFilter$3D$252Faws$252Fbedrock-agentcore$252Fruntimes"),
    ]
    if account_id:
        links.append(("ECR (MCP server image)",
                      f"{base}/ecr/repositories/private/{account_id}/"
                      f"{cfg.ecr_repo}?region={region}"))
        links.append(("CodeBuild (MCP server image build history)",
                      f"{base}/codesuite/codebuild/{account_id}/projects/"
                      f"{cfg.cb_project}/history?region={region}"))
        if include_agent:
            # The hosted agent gets its own image build (hosting.py) -- the
            # one most likely to need debugging when `agent --runtime
            # agentcore` misbehaves, so it deserves its own pair of links.
            links.append(("ECR (hosted agent image)",
                          f"{base}/ecr/repositories/private/{account_id}/"
                          f"{cfg.agent_ecr_repo}?region={region}"))
            links.append(("CodeBuild (hosted agent image build history)",
                          f"{base}/codesuite/codebuild/{account_id}/projects/"
                          f"{cfg.cb_project}-agent/history?region={region}"))
    if pool_id:
        # This pool is machine-to-machine only (client_credentials; it never
        # has users), so land on the app clients page where the gateway's
        # client and resource server actually live -- not an empty Users tab.
        links.append(("Cognito app client (gateway auth)",
                      f"{base}/cognito/v2/idp/user-pools/{pool_id}"
                      f"/applications/app-clients?region={region}"))
    return links


def console_links_lines(cfg, account_id=None, gateway_id=None, pool_id=None,
                        include_agent=True, indent="  "):
    """The 'Open in the AWS Console' block, pre-formatted for the deploy/verify
    summaries: short label line, then the URL ALONE on the next line -- console
    URLs are ~200 chars, and a padded label column forces them to wrap
    mid-screen; on their own line they soft-wrap from a fresh indent and the
    terminal keeps the whole link clickable. [] when there is no stack."""
    links = console_links(cfg, account_id, gateway_id=gateway_id, pool_id=pool_id,
                          include_agent=include_agent)
    if not links:
        return []
    lines = ["", f"{indent}Open in the AWS Console:"]
    for label, url in links:
        lines.append(f"{indent}  • {label}")
        lines.append(f"{indent}    {url}")
    return lines
