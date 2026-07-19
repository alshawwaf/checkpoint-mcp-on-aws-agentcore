#!/usr/bin/env python3
"""DEPRECATED shim -- the implementation moved to the chkpmcpaws package.

Equivalent command:

    python3 -m chkpmcpaws deploy [--servers "..."]

This wrapper keeps existing runbooks working: it forwards --servers (and the
SERVERS env var, which the CLI still honors) straight to `chkpmcpaws deploy` and
exits with the CLI's exit code. Same stack, same fixed resource names.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from chkpmcpaws.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.stderr.write("[deprecated] scripts/build.py forwards to: python3 -m chkpmcpaws deploy\n")
    sys.exit(main(["deploy"] + sys.argv[1:]))
