"""Shared test isolation.

A developer's real local ``.env`` / exports must never steer a unit test into a
live Guard API call: ``_main`` auto-loads ``./.env`` (so ``chat``/``deploy``
pick up ``LAKERA_API_KEY`` without an export), and any test that drives
``cli.main`` would otherwise pull those real creds -- and the ambient
``CHKP_GUARDRAIL_PROVIDER=lakera`` -- into ``os.environ`` for the rest of the
suite. This autouse fixture neutralises the CLI's ``.env`` autoload and clears
the guardrail env around every test so the suite is hermetic and network-free
(the real ``config.load_env_file`` is untouched, so its own unit tests still
exercise it against a tmp file).
"""

import os

import pytest

from chkpmcpaws import cli


@pytest.fixture(autouse=True)
def _isolate_guardrail_env(monkeypatch):
    monkeypatch.setattr(cli, "load_env_file", lambda *a, **k: [], raising=False)
    for k in [k for k in os.environ
              if k == "CHKP_GUARDRAIL_PROVIDER" or k.startswith("LAKERA")]:
        monkeypatch.delenv(k, raising=False)
    yield
