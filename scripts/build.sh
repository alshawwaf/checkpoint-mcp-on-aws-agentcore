#!/usr/bin/env bash
###############################################################################
# build.sh -- thin CloudShell/bash bootstrap.
#
#   bash scripts/build.sh
#   SERVERS="quantum-management harmony-sase" bash scripts/build.sh
#
# The full implementation now lives in the chkpmcpaws Python package (one
# cross-platform code path instead of a parallel bash port that could drift).
# This wrapper just ensures python3 + boto3 exist -- AWS CloudShell ships both
# -- and forwards to:
#
#   python3 -m chkpmcpaws deploy
#
# It still honors SERVERS="..." exactly like the original bash build did.
# Deploys the same stack with the same fixed resource names as before.
###############################################################################
set -euo pipefail
cd "$(dirname "$0")/.."

command -v python3 >/dev/null 2>&1 || { echo "python3 is required (AWS CloudShell ships it)"; exit 1; }
python3 -c "import boto3" >/dev/null 2>&1 || {
  echo "boto3 not found -- installing (python3 -m pip install --upgrade boto3)"
  python3 -m pip install --quiet --upgrade boto3
}

ARGS=(deploy)
if [ -n "${SERVERS:-}" ]; then ARGS+=(--servers "$SERVERS"); fi
exec python3 -m chkpmcpaws "${ARGS[@]}" "$@"
