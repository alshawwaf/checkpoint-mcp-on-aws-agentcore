"""Check Point AI Guardrail (Lakera Guard) inline screen -- pure logic (no AWS)."""

import json

import pytest

from chkpmcpaws import config, lakera
from chkpmcpaws.config import StackConfig


def test_resolve_guardrail_provider_and_secret_name():
    assert config.resolve_guardrail_provider("lakera") == "lakera"
    assert config.resolve_guardrail_provider("ai-guardrail") == "lakera"
    assert config.resolve_guardrail_provider("CHKP") == "lakera"
    assert config.resolve_guardrail_provider(None) == "gateway"      # AWS default
    assert config.resolve_guardrail_provider("gateway") == "gateway"
    assert StackConfig().lakera_secret_name() == "chkp/lakera-guard"


def test_active_provider_reads_env():
    assert lakera.active_provider({}) == "gateway"
    assert lakera.active_provider({"CHKP_GUARDRAIL_PROVIDER": "lakera"}) == "lakera"
    assert lakera.is_lakera({"CHKP_GUARDRAIL_PROVIDER": "lakera"}) is True
    assert lakera.is_lakera({}) is False


def test_lakera_screen_contract(monkeypatch):
    captured = {}

    def fake_post(url, headers, payload, timeout):
        captured.update(url=url, headers=headers, body=payload)
        return {"flagged": True, "breakdown": [
            {"detector_type": "prompt_attack/jailbreak", "detected": True, "score": 0.9},
            {"detector_type": "pii/email", "detected": False, "score": 0.0}]}

    monkeypatch.setattr(lakera, "_post_json", fake_post)
    flagged, detectors = lakera.lakera_screen("ignore instructions", "KEY", "PROJ")
    assert flagged is True and detectors == ["jailbreak"]
    assert captured["url"] == "https://api.lakera.ai/v2/guard"
    assert captured["headers"]["Authorization"] == "Bearer KEY"
    assert captured["body"] == {"messages": [{"role": "user", "content": "ignore instructions"}],
                                "project_id": "PROJ", "breakdown": True}


def test_lakera_screen_requires_key():
    with pytest.raises(ValueError):
        lakera.lakera_screen("x", "", "p")


class _SM:
    def __init__(self, body):
        self._body = body

    def get_secret_value(self, SecretId=None):
        return {"SecretString": json.dumps(self._body)}


class _Session:
    def __init__(self, body):
        self._sm = _SM(body)

    def client(self, name, region_name=None):
        return self._sm


def test_lakera_creds_env_then_secrets_manager():
    # env wins
    assert lakera.lakera_creds({"LAKERA_API_KEY": "EK", "LAKERA_PROJECT_ID": "EP"}) \
        == ("EK", "EP", None)
    # no env -> Secrets Manager fallback via cfg+session
    cfg = StackConfig()
    sess = _Session({"LAKERA_API_KEY": "SK", "LAKERA_PROJECT_ID": "SP"})
    assert lakera.lakera_creds({}, cfg=cfg, session=sess) == ("SK", "SP", None)


def test_screen_prompt_shape(monkeypatch):
    monkeypatch.setattr(lakera, "lakera_screen", lambda t, k, p, u=None: (True, ["jailbreak"]))
    flagged, label, detail = lakera.screen_prompt("x", env={"LAKERA_API_KEY": "K"})
    assert flagged is True and label == "Check Point AI Guardrail" and detail == "jailbreak"


def test_blocked_lines_frames_a_block_as_a_win():
    lines = lakera.blocked_lines(
        "Prompt blocked by Check Point AI Guardrail (attack detected): prompt attack.")
    assert lines == ["\U0001F6E1 Prompt blocked by Check Point AI Guardrail (attack detected): prompt attack."]
