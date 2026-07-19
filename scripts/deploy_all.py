#!/usr/bin/env python3
"""DEPRECATED shim -- the implementation moved to the chkpmcpaws package.

Deploy is now MCP-tools-only; the AWS-native guardrail is a separate, optional
demo (NOT Check Point runtime protection -- that integration is Early Access).
This shim deploys the MCP tools, and if the old --with-guardrail flag is passed
it additionally provisions the guardrail demo and prints where it moved.

    python3 -m chkpmcpaws deploy [--servers "..."]     # MCP tools
    python3 -m chkpmcpaws guardrail provision [--enforce]   # optional demo
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from chkpmcpaws.cli import main  # noqa: E402

if __name__ == "__main__":
    argv = [a for a in sys.argv[1:] if a not in ("--with-guardrail", "--tools-only")]
    want_guardrail = "--with-guardrail" in sys.argv[1:]
    enforce = "--enforce" in argv
    argv = [a for a in argv if a != "--enforce"]
    sys.stderr.write(
        "[deprecated] scripts/deploy_all.py -> python3 -m chkpmcpaws deploy"
        + ("  (guardrail is now the separate 'chkpmcpaws guardrail provision')\n" if want_guardrail else "\n")
    )
    rc = main(["deploy"] + argv)
    if rc == 0 and want_guardrail:
        rc = main(["guardrail", "provision"] + (["--enforce"] if enforce else []))
    sys.exit(rc)
