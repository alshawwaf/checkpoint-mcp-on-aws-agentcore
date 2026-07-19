"""Name-derivation contract: with no prefix, StackConfig must reproduce the
EXACT legacy (field-tested) names, or verify/teardown lose already-deployed
stacks. With a prefix, every derived name must stay legal for its service."""

import re

import pytest

from chkpmcpaws import config
from chkpmcpaws.config import SERVER_CATALOG, StackConfig, parse_servers


def test_legacy_names_exact():
    cfg = StackConfig()
    assert cfg.ecr_repo == "bedrock-agentcore-chkpmcp"
    assert cfg.secret_name("quantum-management") == "chkp/quantum-management"
    assert cfg.rt_role == "AgentCoreRuntimeChkpMcp"
    assert cfg.gw_role == "AgentCoreGatewayRole"
    assert cfg.cb_role == "ChkpMcpCodeBuild"
    assert cfg.cb_project == "chkp-mcp-build"
    assert cfg.gateway_name == "chkp-mcp-gw"
    assert cfg.pool_name == "gateway-user-pool"
    assert cfg.app_client_name == "gateway-client"
    assert cfg.res_server == "gateway-resource-server"
    assert cfg.src_bucket("123456789012") == "chkp-mcp-src-123456789012"
    assert cfg.cognito_domain("123456789012") == "chkp-mcp-gw-123456789012"
    assert (
        cfg.image_uri("123456789012")
        == "123456789012.dkr.ecr.us-east-1.amazonaws.com/bedrock-agentcore-chkpmcp:v1"
    )
    assert cfg.runtime_name("quantum-management") == "chkp_quantum_management"
    assert cfg.runtime_scan_prefix == "chkp_"
    assert cfg.target_name("quantum-management") == "quantummanagement"
    # Mode B guardrail names
    assert cfg.engine_name == "chkp_guardrail_engine"
    assert cfg.permit_policy == "chkp_guardrail_baseline_permit"
    assert cfg.guardrail_policy == "chkp_guardrail_block_prompt_injection"
    assert cfg.guardrail_gateway_name == "chkp-mcp-gw-guardrail"
    assert cfg.guardrail_target == "guardrailtarget"
    assert cfg.guardrail_role == "AgentCoreGatewayRoleGuardrail"


def test_prefixed_names_legal():
    cfg = StackConfig(prefix="demo2")
    cfg.validate()
    # Runtime names: letters/digits/underscore only.
    assert re.fullmatch(r"[A-Za-z0-9_]+", cfg.runtime_name("quantum-management"))
    assert cfg.runtime_name("quantum-management").startswith(cfg.runtime_scan_prefix)
    # Target names: alphanumeric only (they namespace tools).
    assert re.fullmatch(r"[A-Za-z0-9]+", cfg.target_name("quantum-management"))
    # S3 bucket: lowercase/digits/hyphens.
    assert re.fullmatch(r"[a-z0-9-]+", cfg.src_bucket("123456789012"))
    # Cognito domain: lowercase/digits/hyphens, <= 63 chars.
    dom = cfg.cognito_domain("123456789012")
    assert re.fullmatch(r"[a-z0-9-]{1,63}", dom)
    # Prefixed stack must not collide with legacy names.
    legacy = StackConfig()
    assert cfg.gateway_name != legacy.gateway_name
    assert cfg.runtime_scan_prefix != legacy.runtime_scan_prefix
    assert cfg.secret_name("quantum-management") != legacy.secret_name("quantum-management")


def test_prefix_validation_rejects_bad_input():
    for bad in ("UPPER", "-lead", "way-too-long-prefix", "sp ace", "under_score"):
        with pytest.raises(ValueError):
            StackConfig(prefix=bad).validate()


def test_parse_servers_spaces_and_commas():
    assert parse_servers("a b c") == ("a", "b", "c")
    assert parse_servers("a,b,c") == ("a", "b", "c")
    assert parse_servers("a, b  ,c") == ("a", "b", "c")
    assert parse_servers("") == ()
    assert parse_servers(None) == ()


# Servers left out of `--servers all`: tenant creds not yet validated
# (harmony-sase, workforce-ai), target won't come READY on placeholders
# (argos-erm), or interactive-only auth the gateway can't relay (quantum-gaia).
EXCLUDED_FROM_ALL = {"argos-erm", "harmony-sase", "workforce-ai", "quantum-gaia"}


def test_parse_servers_all_excludes_flagged_servers():
    from chkpmcpaws.config import SERVER_CATALOG
    allset = set(parse_servers("all"))
    assert allset.isdisjoint(EXCLUDED_FROM_ALL)
    assert allset == set(SERVER_CATALOG) - EXCLUDED_FROM_ALL
    assert set(parse_servers("ALL")) == allset          # case-insensitive
    # every excluded server is still known + deployable explicitly
    for s in EXCLUDED_FROM_ALL:
        StackConfig(servers=(s,)).validate()


# --- server catalog + per-SERVER secret model --------------------------------
def test_default_servers_are_nine_that_work_through_the_gateway():
    cfg = StackConfig()
    assert set(cfg.servers) == {
        "quantum-management", "management-logs", "threat-prevention",
        "https-inspection", "policy-insights", "quantum-gw-cli",
        "reputation-service", "threat-emulation", "documentation",
    }
    assert len(cfg.servers) == 9
    # every default server stores a (server-side) secret and works through the gateway
    assert all(cfg.server_needs_creds(s) for s in cfg.servers)
    # opt-in / incompatible servers are NOT in the default set
    for s in ("harmony-sase", "workforce-ai", "quantum-gaia",
              "cloudguard-waf", "spark-management", "argos-erm"):
        assert s not in cfg.servers


def test_every_credentialed_server_gets_its_own_secret():
    cfg = StackConfig()
    assert cfg.secret_name("quantum-management") == "chkp/quantum-management"
    assert cfg.secret_name("management-logs") == "chkp/management-logs"
    assert cfg.secret_name("cloudguard-waf") == "chkp/cloudguard-waf"
    # management-shaped servers share the SHAPE (env-var names) but NOT the secret
    assert cfg.secret_name("quantum-management") != cfg.secret_name("management-logs")
    assert cfg.placeholder_for("quantum-management") == cfg.placeholder_for("management-logs")
    assert "MANAGEMENT_HOST" in cfg.placeholder_for("quantum-management")


def test_gaia_is_agent_side_secret_not_wired_to_container():
    cfg = StackConfig()
    # quantum-gaia has NO server-side secret (nothing wired into its container)...
    assert cfg.server_needs_creds("quantum-gaia") is False
    # ...but it DOES have an agent-side secret the agent reads for elicitation.
    assert cfg.agent_creds_shape("quantum-gaia") == "gaia"
    assert cfg.server_has_secret("quantum-gaia") is True
    assert "GAIA_PASSWORD" in cfg.placeholder_for("quantum-gaia")
    # so the creds workflow now COVERS quantum-gaia (its secret gets written)
    assert cfg.servers_with_creds(
        ["quantum-management", "documentation", "quantum-gaia"]
    ) == ["quantum-management", "documentation", "quantum-gaia"]


def test_new_catalog_servers_present_and_shaped():
    cfg = StackConfig()
    assert cfg.server_needs_creds("harmony-sase") is True
    assert "API_KEY" in cfg.placeholder_for("harmony-sase")
    assert "MANAGEMENT_HOST" in cfg.placeholder_for("harmony-sase")
    assert cfg.server_needs_creds("workforce-ai") is True
    assert "CP_CI_CLIENT_ID" in cfg.placeholder_for("workforce-ai")


def test_all_secret_names_covers_every_stored_secret():
    names = StackConfig().all_secret_names()
    assert "chkp/quantum-management" in names
    assert "chkp/cloudguard-waf" in names and "chkp/argos-erm" in names
    assert "chkp/documentation" in names
    assert "chkp/harmony-sase" in names and "chkp/workforce-ai" in names
    assert "chkp/quantum-gaia" in names  # agent-side secret is still torn down
    stored = [s for s in SERVER_CATALOG if StackConfig().server_has_secret(s)]
    assert len(names) == len(stored)
    assert len(set(names)) == len(names)  # all distinct


def test_prefix_applies_to_per_server_secrets():
    cfg = StackConfig(prefix="demo2")
    assert cfg.secret_name("quantum-management") == "chkp/quantum-management-demo2"
    assert cfg.secret_name("cloudguard-waf") == "chkp/cloudguard-waf-demo2"


def test_validate_rejects_unknown_server():
    with pytest.raises(ValueError):
        StackConfig(servers=("quantum-management", "not-a-real-server")).validate()
    StackConfig(servers=("reputation-service",)).validate()  # known -> ok


# --- AgentCore Memory names (opt-in) -----------------------------------------
def test_memory_name_matches_aws_charset():
    # CreateMemory.name pattern is [a-zA-Z][a-zA-Z0-9_]{0,47}: underscores, no hyphens.
    for cfg in (StackConfig(), StackConfig(prefix="demo2")):
        name = cfg.memory_name
        assert re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]{0,47}", name), name
    assert StackConfig().memory_name == "chkp_mcp_memory"
    assert StackConfig(prefix="demo2").memory_name == "chkp_mcp_memory_demo2"
    # role follows the hyphen style like the other IAM roles, and is prefixed
    assert StackConfig().memory_role == "AgentCoreMemoryChkp"
    assert StackConfig(prefix="demo2").memory_role == "AgentCoreMemoryChkp-demo2"


def test_bridge_names():
    cfg = StackConfig()
    assert cfg.bridge_fn == "chkp-agent-bridge"
    assert cfg.bridge_role == "AgentBridgeChkp"
    assert cfg.bridge_secret == "chkp/agent-bridge"
    p = StackConfig(prefix="demo2")
    assert p.bridge_fn == "chkp-agent-bridge-demo2"
    assert p.bridge_secret == "chkp/agent-bridge-demo2"


def test_hosted_agent_runtime_name_caught_by_teardown_scan():
    # The hosted-agent runtime MUST start with the runtime scan prefix so the
    # existing teardown removes it with the MCP-server runtimes.
    for cfg in (StackConfig(), StackConfig(prefix="demo2")):
        assert cfg.agent_runtime_name.startswith(cfg.runtime_scan_prefix)
        assert re.fullmatch(r"[A-Za-z0-9_]+", cfg.agent_runtime_name)
    assert StackConfig().agent_runtime_name == "chkp_agent"
    assert StackConfig().agent_ecr_repo == "bedrock-agentcore-chkpmcp-agent"
    assert StackConfig(prefix="d2").agent_ecr_repo == "bedrock-agentcore-chkpmcp-agent-d2"


def test_pkg_spec_pins_catalog_version():
    cfg = StackConfig()
    # deploy runs a version-pinned npm spec so a demo is reproducible
    assert cfg.pkg_spec("quantum-management") == "@chkp/quantum-management-mcp@1.4.7"
    assert cfg.pkg_spec("reputation-service") == "@chkp/reputation-service-mcp@1.3.1"
    # every catalog server yields a pinned spec (all have a version)
    for s in SERVER_CATALOG:
        assert cfg.pkg_spec(s) == f"@chkp/{s}-mcp@{SERVER_CATALOG[s]['version']}"
    # an unknown server falls back to the unpinned name (never crashes a deploy)
    assert cfg.pkg_spec("made-up") == "@chkp/made-up-mcp"


# =============================================================================
# console_links -- clickable AWS Console links printed after deploy / in verify.
# =============================================================================

_ACCT = "123456789012"
_GW_ID = "chkp-mcp-gw-abc123"
_POOL_ID = "us-east-1_Ab1Cd2Ef3"


def test_console_links_full_ids_build_all_links_umbrella_first():
    cfg = StackConfig(region="eu-west-2")
    links = config.console_links(cfg, _ACCT, gateway_id=_GW_ID, pool_id=_POOL_ID)
    labels = [l for l, _ in links]
    assert labels[0].startswith("Everything, by tag")     # umbrella link first
    assert len(links) == 10
    urls = dict(links)
    # every URL is region-aware and stays on the commercial partition
    for url in urls.values():
        assert url.startswith("https://eu-west-2.console.aws.amazon.com/")
        assert "region=eu-west-2" in url
    joined = " ".join(u for _, u in links)
    assert config.PROJECT_TAG in urls[labels[0]]           # tag filter embedded
    # the umbrella link is stack-scoped, not just project-scoped -- a prefixed
    # stack's summary must not list every chkp stack in the account
    assert "%28key:stack,values:!%28default%29%29" in urls[labels[0]]
    assert f"#/gateways/{_GW_ID}" in joined                # gateway deep link
    assert "search=chkp%2F" in joined                      # secrets list filtered
    assert f"/{_ACCT}/bedrock-agentcore-chkpmcp?" in joined         # ECR repo
    assert f"/{_ACCT}/projects/chkp-mcp-build/history" in joined    # CodeBuild
    # the hosted agent's second image build gets its own pair of links
    assert f"/{_ACCT}/bedrock-agentcore-chkpmcp-agent?" in joined   # agent ECR
    assert f"/{_ACCT}/projects/chkp-mcp-build-agent/history" in joined
    # Cognito lands on the app clients page (an M2M pool never has users)
    assert f"/user-pools/{_POOL_ID}/applications/app-clients" in joined
    # links carry only resource names/ids -- never a credential value
    assert "PLACEHOLDER" not in joined


def test_console_links_no_agent_skips_the_agent_image_links():
    cfg = StackConfig(region="eu-west-2")
    links = config.console_links(cfg, _ACCT, gateway_id=_GW_ID, pool_id=_POOL_ID,
                                 include_agent=False)
    labels = [l for l, _ in links]
    assert len(links) == 8
    assert not any("hosted agent image" in l for l in labels)
    joined = " ".join(u for _, u in links)
    assert "bedrock-agentcore-chkpmcp-agent" not in joined
    assert "chkp-mcp-build-agent" not in joined


def test_console_links_missing_ids_are_skipped_not_broken():
    cfg = StackConfig()
    links = config.console_links(cfg)          # region only -- nothing resolved
    labels = [l for l, _ in links]
    assert len(links) == 5                     # account-/pool-scoped links skipped
    assert not any("ECR" in l for l in labels)
    assert not any("CodeBuild" in l for l in labels)
    assert not any("Cognito" in l for l in labels)
    # no gateway_id -> the list page fallback, not a broken deep link
    gw = dict(links)["AgentCore gateways"]
    assert gw.endswith("#/gateways")


def test_console_links_empty_without_a_stack():
    assert config.console_links(None) == []
    class _NoRegion:
        region = ""
    assert config.console_links(_NoRegion()) == []


def test_console_links_prefix_aware_names():
    cfg = StackConfig(prefix="demo2")
    joined = " ".join(u for _, u in config.console_links(cfg, _ACCT))
    assert "bedrock-agentcore-chkpmcp-demo2" in joined
    assert "chkp-mcp-build-demo2" in joined
    assert "bedrock-agentcore-chkpmcp-agent-demo2" in joined   # agent ECR
    assert "chkp-mcp-build-demo2-agent/history" in joined      # agent CodeBuild
    # the umbrella tag link is narrowed to THIS stack's tag, so a demo2
    # summary never lists the default stack's resources
    assert "%28key:stack,values:!%28demo2%29%29" in joined
    assert "%28key:stack,values:!%28default%29%29" not in joined


def test_console_links_lines_puts_each_url_on_its_own_line():
    lines = config.console_links_lines(StackConfig(), _ACCT,
                                       gateway_id=_GW_ID, pool_id=_POOL_ID)
    assert lines[1].strip() == "Open in the AWS Console:"
    # alternating label / URL pairs -- a URL line contains ONLY the url
    url_lines = [l for l in lines if "https://" in l]
    assert len(url_lines) == 10
    for l in url_lines:
        assert l.strip().startswith("https://")     # nothing shares the line
    label_lines = [l for l in lines if l.strip().startswith("•")]
    assert len(label_lines) == 10


def test_console_links_lines_empty_without_a_stack():
    assert config.console_links_lines(None) == []


# --------------------------------------------------------------------------
# Guardrail credential UX: LAKERA_GUARD_* aliases + local .env autoload.
# --------------------------------------------------------------------------

def test_lakera_env_canonical_names():
    env = {"LAKERA_API_KEY": "k", "LAKERA_PROJECT_ID": "p", "LAKERA_API_URL": "u"}
    assert config.lakera_env(env) == ("k", "p", "u")


def test_lakera_env_accepts_guard_aliases():
    # An operator's existing LAKERA_GUARD_* names must keep working.
    env = {"LAKERA_GUARD_API_KEY": "k", "LAKERA_GUARD_PROJECT_ID": "p",
           "LAKERA_GUARD_URL": "u"}
    assert config.lakera_env(env) == ("k", "p", "u")


def test_lakera_env_canonical_wins_over_alias():
    env = {"LAKERA_API_KEY": "canon", "LAKERA_GUARD_API_KEY": "old"}
    assert config.lakera_env(env)[0] == "canon"


def test_lakera_env_url_alias_variants():
    assert config.lakera_env({"LAKERA_GUARD_API_URL": "u"})[2] == "u"


def test_lakera_env_absent_is_empty_key_and_none():
    assert config.lakera_env({}) == ("", None, None)


def test_load_env_file_missing_is_noop(tmp_path):
    assert config.load_env_file(str(tmp_path / "nope.env")) == []


def test_load_env_file_parses_and_respects_explicit_export(tmp_path, monkeypatch):
    p = tmp_path / ".env"
    p.write_text(
        "# a comment\n"
        "[section-should-be-skipped]\n"
        'export LAKERA_API_KEY="abc=def"\n'   # export prefix + quotes + '=' in value
        "LAKERA_PROJECT_ID = pid \n"          # surrounding whitespace
        "PRESET=fromfile\n"
        "\n"
        "NO_EQUALS_LINE\n"
    )
    fake = {"PRESET": "exported"}             # already-exported var must win
    monkeypatch.setattr(config.os, "environ", fake)
    loaded = config.load_env_file(str(p))
    assert fake["LAKERA_API_KEY"] == "abc=def"      # quotes stripped, '=' preserved, no interpolation
    assert fake["LAKERA_PROJECT_ID"] == "pid"       # trimmed
    assert fake["PRESET"] == "exported"             # explicit env wins over file (setdefault)
    assert set(loaded) == {"LAKERA_API_KEY", "LAKERA_PROJECT_ID"}
def test_load_env_file_strips_utf8_bom(tmp_path, monkeypatch):
    # A Windows/Notepad-saved .env starts with a UTF-8 BOM; the first key must
    # not be corrupted into "﻿LAKERA_API_KEY".
    p = tmp_path / ".env"
    p.write_text("LAKERA_API_KEY=abc\nLAKERA_PROJECT_ID=pid\n", encoding="utf-8-sig")
    fake = {}
    monkeypatch.setattr(config.os, "environ", fake)
    loaded = config.load_env_file(str(p))
    assert fake.get("LAKERA_API_KEY") == "abc"       # BOM stripped, key intact
    assert "LAKERA_API_KEY" in loaded


def test_load_env_file_inline_comment_and_literal_hash(tmp_path, monkeypatch):
    p = tmp_path / ".env"
    p.write_text(
        "A=val  # trailing comment\n"   # unquoted inline comment -> stripped
        "B=frag#ment\n"                 # '#' with no leading space -> kept literally
        'C="quo # ted"  # note\n'       # '#' inside quotes kept; trailing comment dropped
    )
    fake = {}
    monkeypatch.setattr(config.os, "environ", fake)
    config.load_env_file(str(p))
    assert fake["A"] == "val"
    assert fake["B"] == "frag#ment"
    assert fake["C"] == "quo # ted"
