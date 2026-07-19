#!/usr/bin/env bash
###############################################################################
# teardown.sh -- thin CloudShell/bash bootstrap.
#
#   bash scripts/teardown.sh                          # Mode A teardown
#   bash scripts/teardown.sh --force-delete-secret    # purge the secret now
#
# The full implementation now lives in the chkpmcpaws Python package. This
# wrapper preserves the original scope (MCP tools only, no prompt) by forwarding:
#
#   python3 -m chkpmcpaws destroy --tools-only --yes
#
# The secret chkp/mgmt-mcp gets a 7-day recovery window by default (it may
# hold real credentials by go-live); --force-delete-secret restores the old
# purge-immediately behavior. To remove the guardrail AND the MCP tools in the
# safe order:
#
#   python3 -m chkpmcpaws destroy
###############################################################################
set -euo pipefail
cd "$(dirname "$0")/.."

command -v python3 >/dev/null 2>&1 || { echo "python3 is required (AWS CloudShell ships it)"; exit 1; }
python3 -c "import boto3" >/dev/null 2>&1 || {
  echo "boto3 not found -- installing (python3 -m pip install --upgrade boto3)"
  python3 -m pip install --quiet --upgrade boto3
}

exec python3 -m chkpmcpaws destroy --tools-only --yes "$@"
