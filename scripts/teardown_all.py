#!/usr/bin/env python3
"""DEPRECATED shim -- the implementation moved to the chkpmcpaws package.

Equivalent command:

    python3 -m chkpmcpaws destroy

Order is preserved: The guardrail is torn down FIRST (its target references an
MCP tools runtime), then the tools. Both halves stay idempotent and safe to re-run.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from chkpmcpaws.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.stderr.write(
        "[deprecated] scripts/teardown_all.py forwards to: python3 -m chkpmcpaws destroy\n"
    )
    sys.exit(main(["destroy", "--yes"] + sys.argv[1:]))
