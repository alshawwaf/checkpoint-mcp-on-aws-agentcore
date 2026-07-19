#!/usr/bin/env python3
"""DEPRECATED shim -- the implementation moved to the chkpmcpaws package.

Equivalent command:

    python3 -m chkpmcpaws verify

Read-only either way: discovers the deployed stack by its fixed names, mints
a fresh Cognito token, and lists the aggregated tool catalog.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from chkpmcpaws.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.stderr.write("[deprecated] scripts/verify.py forwards to: python3 -m chkpmcpaws verify\n")
    sys.exit(main(["verify"] + sys.argv[1:]))
