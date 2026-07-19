"""chkpmcpaws -- Check Point MCP servers on AWS Bedrock AgentCore.

One package, one CLI, two paths -- MCP tools (Check Point servers hosted as
tools behind one gateway) and an AI guardrail (AWS-native policy enforcement
at a gateway):

    python3 -m chkpmcpaws deploy [--servers ...] [--creds file]   # MCP tools behind one gateway
    python3 -m chkpmcpaws chat "..." [--session id] [--runtime local|agentcore] [--guardrail]
    python3 -m chkpmcpaws status [--guardrail]
    python3 -m chkpmcpaws doctor                                  # local preflight, changes nothing
    python3 -m chkpmcpaws creds template|apply
    python3 -m chkpmcpaws guardrail provision|enforce|test|verify|destroy
    python3 -m chkpmcpaws destroy [--tools-only|--guardrail-only] [--yes]

Aliases (kept for compatibility, hidden from --help): `agent` -> `chat`,
`verify` -> `status`. The legacy entry points under scripts/ still work; they
forward here.
"""

__version__ = "0.2.0"
