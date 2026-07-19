"""Local credentials workflow.

Keep Check Point credentials in a gitignored .env-style file -- one
``[server]`` section per server, plain ``KEY=VALUE`` lines -- then apply them to
the per-server Secrets Manager secrets and restart the affected runtimes so
they re-read them:

    python3 -m chkpmcpaws creds template   # write a starter file for your servers
    # edit chkp-credentials.env with real values
    python3 -m chkpmcpaws creds apply      # write the secrets + refresh runtimes

Each ``[section]`` is a SERVER name; its ``KEY=VALUE`` lines become that
server's own ``chkp/<server>`` secret verbatim. Two servers can therefore hold
entirely different credentials. Values are NEVER printed or committed (the file
is gitignored; only server and key NAMES are ever logged).

Backward compatible: an existing JSON file (``chkp-credentials.json``, keyed by
server) is still read if present and no .env exists.
"""

import configparser
import io
import json
import os

from . import build, config
from .awsutil import (
    ClientError,
    agentcore_client,
    err_code,
    log,
    paginate,
    resolve_account,
)

DEFAULT_CREDS_FILE = "chkp-credentials.env"
LEGACY_JSON_FILE = "chkp-credentials.json"

_TEMPLATE_HEADER = (
    "# Check Point credentials for chkpmcpaws -- gitignored, NEVER commit.\n"
    "# One [section] per SERVER; each KEY=VALUE becomes that server's own\n"
    "# chkp/<server> Secrets Manager secret. Fill in real values, then run:\n"
    "#   python3 -m chkpmcpaws creds apply\n"
)


def _server_credor(text):
    """Parse .env / INI text into {server: {KEY: value}}. Case-preserving;
    no % interpolation (API keys may contain % or =)."""
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str  # preserve KEY case (env vars are case-sensitive)
    try:
        parser.read_string(text)
    except configparser.MissingSectionHeaderError:
        raise ValueError(
            "each server's credentials need a [section] header, e.g. "
            "[quantum-management] above its KEY=VALUE lines"
        )
    except configparser.Error as e:
        raise ValueError(str(e))
    return {section: dict(parser[section]) for section in parser.sections()}


def parse_creds_text(text):
    """Public entry for tests: .env text -> {server: {KEY: value}}."""
    return _server_credor(text)


def _deployed_servers(cfg, session):
    """Servers whose runtimes are actually deployed (so the template matches
    reality). Falls back to the configured server set if none found."""
    ac = agentcore_client(session, cfg.region)
    scan = cfg.runtime_scan_prefix
    us_to_server = {s.replace("-", "_"): s for s in config.SERVER_CATALOG}
    deployed = []
    for rt in paginate(ac.list_agent_runtimes):
        name = str(rt.get("agentRuntimeName", ""))
        if name.startswith(scan):
            server = us_to_server.get(name[len(scan):])
            if server:
                deployed.append(server)
    return cfg.servers_with_creds(deployed or list(cfg.servers))


def template(cfg, session, path=None):
    path = path or DEFAULT_CREDS_FILE
    if os.path.exists(path):
        log(f"{path} already exists -- refusing to overwrite (it may hold real creds).")
        log("Edit it, or pass --file <path> for a different location.")
        return 1
    servers = _deployed_servers(cfg, session)
    if not servers:
        log("No servers needing credentials (only credential-free servers deployed).")
        return 0
    buf = io.StringIO()
    buf.write(_TEMPLATE_HEADER)
    for s in servers:
        buf.write(f"\n[{s}]\n")
        for k, v in cfg.placeholder_for(s).items():
            buf.write(f"{k}={v}\n")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(buf.getvalue())
    log(f"Wrote {path} with {len(servers)} server section(s): {', '.join(servers)}")
    log("Edit the values (it is gitignored), then: python3 -m chkpmcpaws creds apply")
    return 0


def load_file(path):
    """Public: parse a creds file (.env or legacy .json) into
    {server: {KEY: value}}. Used by `deploy --creds`. Raises OSError/ValueError."""
    return _load(path)


def _load(path):
    """Read the creds file into {server: {KEY: value}} (JSON or .env)."""
    with open(path, encoding="utf-8") as fh:
        raw = fh.read()
    if path.endswith(".json"):
        doc = json.loads(raw)
        if not isinstance(doc, dict):
            raise ValueError("JSON creds file must be an object of {server: {KEY: value}}")
        # drop legacy "_note" style meta keys
        return {k: v for k, v in doc.items() if not k.startswith("_")}
    return _server_credor(raw)


def apply(cfg, session, path=None):
    if path is None:
        if os.path.exists(DEFAULT_CREDS_FILE):
            path = DEFAULT_CREDS_FILE
        elif os.path.exists(LEGACY_JSON_FILE):
            path = LEGACY_JSON_FILE
            log(f"Using legacy {LEGACY_JSON_FILE}; new templates write "
                f"{DEFAULT_CREDS_FILE} (KEY=VALUE).")
        else:
            path = DEFAULT_CREDS_FILE
    if not os.path.exists(path):
        log(f"No creds file at {path}. Create one first: python3 -m chkpmcpaws creds template")
        return 1
    try:
        doc = _load(path)
    except (OSError, ValueError) as e:
        log(f"Could not read {path}: {e}")
        return 1

    region = cfg.region
    sm = session.client("secretsmanager", region_name=region)
    resolve_account(session, region)  # surfaces credential/root warnings early

    applied, skipped = [], []
    for server, body in doc.items():
        if not cfg.server_needs_creds(server):
            known = ", ".join(s for s in config.SERVER_CATALOG if cfg.server_needs_creds(s))
            log(f"  skipping '{server}': not a credentialed server (known: {known})")
            skipped.append(server)
            continue
        if not isinstance(body, dict) or not body:
            log(f"  skipping '{server}': section has no KEY=VALUE lines")
            skipped.append(server)
            continue
        # Guard against applying an unedited template.
        if any(str(v).startswith("PLACEHOLDER") or str(v).startswith("replace-with")
               for v in body.values()):
            log(f"  '{server}' still has placeholder values -- edit them before applying; skipping")
            skipped.append(server)
            continue
        name = cfg.secret_name(server)
        payload = json.dumps(body)
        try:
            sm.put_secret_value(SecretId=name, SecretString=payload)
        except ClientError as e:
            if err_code(e) == "ResourceNotFoundException":
                sm.create_secret(Name=name, SecretString=payload, Tags=cfg.tags_kv())
            elif err_code(e) == "InvalidRequestException" and "deletion" in str(e).lower():
                sm.restore_secret(SecretId=name)
                sm.put_secret_value(SecretId=name, SecretString=payload)
            else:
                raise
        log(f"  {server} -> {name}  ({len(body)} key(s) set; values not printed)")
        applied.append(server)

    if not applied:
        log("No servers applied (nothing valid in the file). Nothing to refresh.")
        return 1 if skipped else 0

    log(f"\nApplied {len(applied)} secret(s): {', '.join(applied)}. Restarting runtimes so they re-read...")
    # build.refresh runs the live UI and cycles every runtime (re-reading all
    # secrets). Safe superset of "the affected runtimes".
    rc = build.refresh(cfg, session)
    return rc
