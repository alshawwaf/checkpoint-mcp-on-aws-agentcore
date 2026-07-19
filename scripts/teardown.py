#!/usr/bin/env python3
"""DEPRECATED shim -- the implementation moved to the chkpmcpaws package.

Equivalent command:

    python3 -m chkpmcpaws destroy --tools-only [--force-delete-secret]

This wrapper preserves the original behavior (MCP-tools-only, no confirmation
prompt) by passing --yes. The secret now gets a 7-day recovery window by
default; pass --force-delete-secret for the old purge-immediately behavior.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from chkpmcpaws.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.stderr.write(
        "[deprecated] scripts/teardown.py forwards to: python3 -m chkpmcpaws destroy --tools-only\n"
    )
    sys.exit(main(["destroy", "--tools-only", "--yes"] + sys.argv[1:]))
