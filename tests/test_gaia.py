"""Pure-logic tests for the Gaia login elicitation answerer (no AWS/MCP calls)."""

import asyncio

from chkpmcpaws.gaia import (
    is_configured,
    make_elicitation_callback,
    _value_for,
)

CREDS = {"GAIA_GATEWAY_IP": "10.1.1.5", "GAIA_PORT": "443",
         "GAIA_USER": "admin", "GAIA_PASSWORD": "s3cret"}


def test_is_configured():
    assert is_configured(CREDS) is True
    assert is_configured({"GAIA_GATEWAY_IP": "1.2.3.4"}) is False  # no user/pass
    assert is_configured({}) is False


def test_value_for_aliases_and_type_coercion():
    # field-name aliases map to the right credential
    assert _value_for("gateway_ip", {"type": "string"}, CREDS) == "10.1.1.5"
    assert _value_for("address", {"type": "string"}, CREDS) == "10.1.1.5"
    assert _value_for("user", {"type": "string"}, CREDS) == "admin"
    assert _value_for("password", {"type": "string"}, CREDS) == "s3cret"
    # port coerces to int when the schema asks for a number
    assert _value_for("port", {"type": "integer"}, CREDS) == 443
    assert _value_for("port", {"type": "string"}, CREDS) == "443"
    # unknown field we can't fill -> None
    assert _value_for("totp_code", {"type": "string"}, CREDS) is None


def test_no_callback_without_creds():
    assert make_elicitation_callback({}) is None
    assert make_elicitation_callback({"GAIA_USER": "x"}) is None  # incomplete


class _FormParams:
    """Minimal stand-in for mcp.types.ElicitRequestFormParams."""
    def __init__(self, props, required=None):
        self.requestedSchema = {"properties": props, "required": required or list(props)}


def _run(cb, params):
    return asyncio.run(cb(context=None, params=params))


def test_callback_accepts_and_fills_a_login_form():
    cb = make_elicitation_callback(CREDS)
    params = _FormParams({
        "gateway_ip": {"type": "string"},
        "port": {"type": "integer"},
        "user": {"type": "string"},
        "password": {"type": "string"},
    })
    res = _run(cb, params)
    assert res.action == "accept"
    assert res.content == {"gateway_ip": "10.1.1.5", "port": 443,
                           "user": "admin", "password": "s3cret"}


def test_callback_declines_when_a_required_field_is_unfillable():
    cb = make_elicitation_callback(CREDS)
    # server demands a one-time code we don't have -> decline (fail fast, no hang)
    params = _FormParams({"user": {"type": "string"}, "otp": {"type": "string"}})
    res = _run(cb, params)
    assert res.action == "decline"


def test_callback_handles_partial_gateway_only_prompt():
    # Gaia asks for gateway details first (no creds yet) -- we can fill those.
    cb = make_elicitation_callback(CREDS)
    params = _FormParams({"gateway_ip": {"type": "string"}, "port": {"type": "integer"}})
    res = _run(cb, params)
    assert res.action == "accept"
    assert res.content == {"gateway_ip": "10.1.1.5", "port": 443}
