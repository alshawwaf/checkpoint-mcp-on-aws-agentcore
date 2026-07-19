"""Unit tests for the read-only `doctor` preflight.

`run_doctor` must:
  * touch AWS ONLY through the passed-in session (no real calls here -- the
    session and its clients are stubbed);
  * create/modify NOTHING (it only builds clients + calls sts get-caller-identity);
  * HARD-FAIL (return 1) on python<3.9, a boto3 too old for AgentCore, or
    unresolved credentials;
  * WARN (still return 0) on account-root identity, a region outside the
    optional guardrail set, a missing `mcp` extra, or an old-but-working boto3
    that lacks the optional AgentCore Policy/Memory models.

boto3/subprocess are never invoked for real: `session.client(...)` returns fake
clients, and `get_caller_identity` returns a fixed dict (or raises a botocore
error to exercise the credential FAIL path).
"""

from botocore.exceptions import NoCredentialsError, UnknownServiceError

from chkpmcpaws import doctor
from chkpmcpaws.config import StackConfig
from chkpmcpaws.doctor import FAIL, OK, WARN


# =============================================================================
# Fakes -- no real AWS, no network
# =============================================================================
class _FakeSts:
    def __init__(self, ident=None, exc=None):
        self._ident = ident or {"Account": "123456789012",
                                "Arn": "arn:aws:iam::123456789012:user/demo"}
        self._exc = exc

    def get_caller_identity(self):
        if self._exc:
            raise self._exc
        return self._ident


class _FakeAgentCoreControl:
    def __init__(self, has_policy=True):
        if has_policy:
            self.create_policy_engine = lambda **k: None


class _FakeAgentCoreData:
    def __init__(self, has_memory=True):
        if has_memory:
            self.create_event = lambda **k: None


class _FakeSession:
    """Answers only the three services doctor builds; records every request so a
    test can assert nothing else was ever touched."""

    def __init__(self, *, sts=None, control_unknown=False, data_unknown=False,
                 has_policy=True, has_memory=True):
        self._sts = sts or _FakeSts()
        self._control_unknown = control_unknown
        self._data_unknown = data_unknown
        self._has_policy = has_policy
        self._has_memory = has_memory
        self.requested = []

    def client(self, name, region_name=None):
        self.requested.append(name)
        if name == "sts":
            return self._sts
        if name == "bedrock-agentcore-control":
            if self._control_unknown:
                raise UnknownServiceError(
                    service_name=name, known_service_names="s3, ec2")
            return _FakeAgentCoreControl(has_policy=self._has_policy)
        if name == "bedrock-agentcore":
            if self._data_unknown:
                raise UnknownServiceError(
                    service_name=name, known_service_names="s3, ec2")
            return _FakeAgentCoreData(has_memory=self._has_memory)
        raise AssertionError(f"doctor touched an unexpected service: {name}")


def _cfg(region="us-east-1"):
    return StackConfig(region=region)


def _capture_say(monkeypatch):
    """Record every (status, label, detail) while keeping production behaviour."""
    rec = []

    def _fake_say(status, label, detail=""):
        rec.append((status, label, detail))
        return status

    monkeypatch.setattr(doctor, "_say", _fake_say)
    return rec


# =============================================================================
# Happy path
# =============================================================================
def test_healthy_workstation_returns_zero(monkeypatch, capsys):
    rec = _capture_say(monkeypatch)
    sess = _FakeSession()
    rc = doctor.run_doctor(_cfg(), sess)
    out = capsys.readouterr().out
    assert rc == 0
    assert not any(s == FAIL for s, _, _ in rec)   # no hard failure
    assert "all checks passed" in out
    # read-only: doctor only ever built these three clients
    assert set(sess.requested) == {"sts", "bedrock-agentcore-control",
                                   "bedrock-agentcore"}
    # org-policy + remote-only footers are always printed
    assert "AWS Secrets Manager" in out and "Cognito-JWT" in out
    assert "node / npx" in out and "run remotely" in out


def test_identity_ok_row_present(monkeypatch):
    rec = _capture_say(monkeypatch)
    doctor.run_doctor(_cfg(), _FakeSession())
    assert any(s == OK and "AWS identity" in lbl for s, lbl, _ in rec)


# =============================================================================
# Hard failures -> exit 1
# =============================================================================
def test_missing_credentials_is_hard_fail_but_never_raises(monkeypatch, capsys):
    rec = _capture_say(monkeypatch)
    sess = _FakeSession(sts=_FakeSts(exc=NoCredentialsError()))
    rc = doctor.run_doctor(_cfg(), sess)       # must NOT raise
    out = capsys.readouterr().out
    assert rc == 1
    assert any(s == FAIL and "AWS credentials" in lbl for s, lbl, _ in rec)
    assert "check(s) FAILED" in out            # report still completes
    assert "org policy reminders" in out


def test_expired_token_reports_reauth_advice(monkeypatch):
    from botocore.exceptions import ClientError
    rec = _capture_say(monkeypatch)
    exc = ClientError({"Error": {"Code": "ExpiredToken", "Message": "x"}},
                      "GetCallerIdentity")
    doctor.run_doctor(_cfg(), _FakeSession(sts=_FakeSts(exc=exc)))
    assert any(s == FAIL and "log in again" in detail for s, _, detail in rec)


def test_old_boto3_without_agentcore_is_hard_fail(monkeypatch):
    rec = _capture_say(monkeypatch)
    rc = doctor.run_doctor(_cfg(), _FakeSession(control_unknown=True))
    assert rc == 1
    assert any(s == FAIL and "AgentCore" in lbl for s, lbl, _ in rec)


# =============================================================================
# Warnings -> still exit 0
# =============================================================================
def test_account_root_warns_not_fails(monkeypatch):
    rec = _capture_say(monkeypatch)
    root = _FakeSts(ident={"Account": "123456789012",
                           "Arn": "arn:aws:iam::123456789012:root"})
    rc = doctor.run_doctor(_cfg(), _FakeSession(sts=root))
    assert rc == 0
    assert any(s == WARN and "ROOT" in lbl for s, lbl, _ in rec)


def test_region_outside_guardrail_set_warns_not_fails(monkeypatch):
    rec = _capture_say(monkeypatch)
    rc = doctor.run_doctor(_cfg(region="us-west-2"), _FakeSession())
    assert rc == 0                                  # no hard region gate on AWS
    assert any(s == WARN and "us-west-2" in lbl for s, lbl, _ in rec)


def test_supported_guardrail_region_is_ok(monkeypatch):
    rec = _capture_say(monkeypatch)
    doctor.run_doctor(_cfg(region="eu-west-2"), _FakeSession())
    assert any(s == OK and "eu-west-2" in lbl for s, lbl, _ in rec)


def test_old_boto3_missing_policy_or_memory_only_warns(monkeypatch):
    rec = _capture_say(monkeypatch)
    rc = doctor.run_doctor(_cfg(), _FakeSession(has_policy=False, has_memory=False))
    assert rc == 0                                  # optional features -> WARN
    assert any(s == WARN and "Policy" in lbl for s, lbl, _ in rec)
    assert any(s == WARN and "Memory" in lbl for s, lbl, _ in rec)


def test_mcp_extra_absence_is_a_warning(monkeypatch):
    rec = _capture_say(monkeypatch)
    monkeypatch.setattr(doctor, "mcp_available", lambda: False)
    rc = doctor.run_doctor(_cfg(), _FakeSession())
    assert rc == 0
    assert any(s == WARN and "mcp extra" in lbl for s, lbl, _ in rec)
