"""The local .env creds parser: [server] sections -> {server: {KEY: value}},
case-preserving, tolerant of '=' and special chars in values, and it rejects a
bare KEY=VALUE file with no section header."""

import pytest

from chkpmcpaws.creds import parse_creds_text


def test_sections_become_servers():
    text = (
        "[quantum-management]\n"
        "MANAGEMENT_HOST=host.example\n"
        "API_KEY=abc123\n"
        "\n"
        "[cloudguard-waf]\n"
        "WAF_CLIENT_ID=cid\n"
    )
    doc = parse_creds_text(text)
    assert doc == {
        "quantum-management": {"MANAGEMENT_HOST": "host.example", "API_KEY": "abc123"},
        "cloudguard-waf": {"WAF_CLIENT_ID": "cid"},
    }


def test_key_case_preserved_and_equals_in_value():
    # env vars are case-sensitive; API keys often contain '=' and '+' and '/'.
    doc = parse_creds_text("[s]\nAPI_KEY=+DcTTZeCy7/abc=dyA==\n")
    assert doc["s"]["API_KEY"] == "+DcTTZeCy7/abc=dyA=="


def test_comments_ignored():
    doc = parse_creds_text("# a comment\n[s]\nK=v\n")
    assert doc == {"s": {"K": "v"}}


def test_missing_section_header_is_a_clear_error():
    with pytest.raises(ValueError):
        parse_creds_text("MANAGEMENT_HOST=host\nAPI_KEY=abc\n")
