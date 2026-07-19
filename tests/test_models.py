"""Pure-logic tests for Bedrock model-access automation (no AWS)."""

import json

from chkpmcpaws import models
from chkpmcpaws.config import StackConfig


def test_managed_models_are_claude_base_ids():
    ids = models.managed_model_ids()
    assert ids, "expected at least one managed Claude model"
    # base ids (agreements target the base model, not the us. inference profile)
    assert all(m.startswith("anthropic.") for m in ids)
    assert not any(m.startswith("us.") for m in ids)
    # Nova is Amazon's own -- never managed here
    assert not any("nova" in m for m in ids)


def test_decide_branches():
    assert models.decide({"entitlementAvailability": "AVAILABLE"}) == "already"
    assert models.decide({"entitlementAvailability": "NOT_AVAILABLE",
                          "regionAvailability": "NOT_AVAILABLE"}) == "region"
    assert models.decide({"entitlementAvailability": "NOT_AVAILABLE",
                          "regionAvailability": "AVAILABLE",
                          "authorizationStatus": "NOT_AUTHORIZED"}) == "needs-auth"
    assert models.decide({"entitlementAvailability": "NOT_AVAILABLE",
                          "regionAvailability": "AVAILABLE",
                          "authorizationStatus": "AUTHORIZED"}) == "create"


class _SSM:
    """In-memory SSM stub for the marker parameter."""
    def __init__(self, value=None):
        self.store = {} if value is None else {"v": value}
        self.deleted = False
    def get_parameter(self, Name):
        if "v" not in self.store:
            from chkpmcpaws.awsutil import ClientError
            raise ClientError({"Error": {"Code": "ParameterNotFound", "Message": "x"}}, "GetParameter")
        return {"Parameter": {"Value": self.store["v"]}}
    def put_parameter(self, Name, Value, **kw):
        self.store["v"] = Value
    def add_tags_to_resource(self, **kw):
        pass
    def delete_parameter(self, Name):
        self.deleted = True
        self.store.pop("v", None)


class _BR:
    def __init__(self):
        self.deleted = []
    def create_foundation_model_agreement(self, **kw):  # presence => modern boto3
        pass
    def delete_foundation_model_agreement(self, modelId):
        self.deleted.append(modelId)


def test_disable_enabled_revokes_only_marker_models(monkeypatch):
    cfg = StackConfig()
    ssm = _SSM(value=json.dumps(["anthropic.claude-sonnet-4-5-20250929-v1:0"]))
    br = _BR()
    clients = {"ssm": ssm, "bedrock": br}
    monkeypatch.setattr(
        "boto3.Session.client",
        lambda self, name, **kw: clients[name], raising=False)
    import boto3
    out = models.disable_enabled(cfg, boto3.Session())
    assert br.deleted == ["anthropic.claude-sonnet-4-5-20250929-v1:0"]
    assert ssm.deleted is True            # marker removed
    assert "revoked 1" in out


def test_disable_noop_without_marker(monkeypatch):
    cfg = StackConfig()
    ssm = _SSM(value=None)  # no marker
    monkeypatch.setattr("boto3.Session.client",
                        lambda self, name, **kw: ssm, raising=False)
    import boto3
    assert models.disable_enabled(cfg, boto3.Session()) is None


def test_model_access_param_prefix_aware():
    assert StackConfig().model_access_param == "/chkp/model-access"
    assert StackConfig(prefix="demo2").model_access_param == "/chkp/model-access-demo2"


# --- use-case-form detection (entitled but not invocable) --------------------
def _client_error(code, message):
    from chkpmcpaws.awsutil import ClientError
    return ClientError({"Error": {"Code": code, "Message": message}}, "Converse")


class _RT:
    def __init__(self, exc):
        self._exc = exc

    def converse(self, **kw):
        if self._exc:
            raise self._exc
        return {"output": {"message": {"content": []}}}


class _Sess:
    def __init__(self, exc):
        self._rt = _RT(exc)

    def client(self, name, **kw):
        return self._rt


def test_use_case_form_blocking_classifies_the_ping():
    form = _client_error("ResourceNotFoundException",
                         "Model use case details have not been submitted for this account.")
    other = _client_error("AccessDeniedException", "not authorized")
    # the unsubmitted use-case form is detected...
    assert models._use_case_form_blocking(_Sess(form), "us-east-1") is True
    # ...a clean ping is not blocking...
    assert models._use_case_form_blocking(_Sess(None), "us-east-1") is False
    # ...and any other error is not misreported as the form gap.
    assert models._use_case_form_blocking(_Sess(other), "us-east-1") is False
