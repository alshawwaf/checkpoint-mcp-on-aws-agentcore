"""Global options (--profile/--region/--prefix) must work both before and
after the subcommand, like the AWS CLI -- and a value given before the
subcommand must survive the subparser (SUPPRESS defaults, no clobbering)."""

import argparse

from chkpmcpaws.cli import _build_parser


def _subparsers_action(parser):
    """The argparse _SubParsersAction on the root parser (holds the subcommand
    name->parser map and the help-visible choices)."""
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action
    raise AssertionError("no subparsers action found")


def test_globals_after_subcommand():
    args = _build_parser().parse_args(["deploy", "--profile", "sandbox", "--region", "eu-west-2"])
    assert args.profile == "sandbox"
    assert args.region == "eu-west-2"


def test_globals_before_subcommand_survive_subparser():
    args = _build_parser().parse_args(["--profile", "sandbox", "--prefix", "stack2", "verify"])
    assert args.profile == "sandbox"
    assert args.prefix == "stack2"


def test_globals_absent_when_never_passed():
    args = _build_parser().parse_args(["destroy", "--yes"])
    assert not hasattr(args, "profile")
    assert not hasattr(args, "region")
    assert not hasattr(args, "prefix")


def test_subcommand_position_wins_when_both_given():
    args = _build_parser().parse_args(["--profile", "a", "deploy", "--profile", "b"])
    assert args.profile == "b"


def test_guardrail_action_with_globals():
    args = _build_parser().parse_args(["guardrail", "test", "--profile", "sandbox"])
    assert args.action == "test"
    assert args.profile == "sandbox"


def test_agent_task_optional_for_examples():
    p = _build_parser()
    assert p.parse_args(["agent"]).task is None  # bare agent -> show examples
    assert p.parse_args(["agent", "how many hosts?"]).task == "how many hosts?"


def test_deploy_creds_flag():
    p = _build_parser()
    assert p.parse_args(["deploy"]).creds is None
    assert p.parse_args(["deploy", "--creds"]).creds == "chkp-credentials.env"
    assert p.parse_args(["deploy", "--creds", "my.env"]).creds == "my.env"


def test_bridge_subcommand_parses():
    p = _build_parser()
    for action in ("provision", "show", "destroy"):
        assert p.parse_args(["bridge", action]).action == action
    assert p.parse_args(["bridge", "show", "--reveal-token"]).reveal_token is True


def test_deploy_hosted_agent_default_on_with_opt_out():
    p = _build_parser()
    # hosted agent runtime ships by default; --no-agent skips it
    assert p.parse_args(["deploy"]).no_agent is False
    assert p.parse_args(["deploy", "--no-agent"]).no_agent is True


def test_new_command_surface_parses():
    p = _build_parser()
    # The guardrail is demoted off the deploy path: deploy is MCP-tools-only.
    assert not hasattr(p.parse_args(["deploy"]), "with_guardrail")
    assert p.parse_args(["agent", "how many hosts?"]).task == "how many hosts?"
    assert p.parse_args(["verify", "--guardrail"]).guardrail is True
    assert p.parse_args(["destroy", "--tools-only", "--yes"]).tools_only is True
    assert p.parse_args(["destroy", "--guardrail-only", "--yes"]).guardrail_only is True
    for action in ("provision", "enforce", "test", "verify", "destroy"):
        assert p.parse_args(["guardrail", action]).action == action


def test_deploy_no_longer_accepts_with_guardrail():
    p = _build_parser()
    import pytest
    with pytest.raises(SystemExit):
        p.parse_args(["deploy", "--with-guardrail"])


def test_models_subcommand_parses():
    p = _build_parser()
    for action in ("enable", "status", "disable"):
        assert p.parse_args(["models", action]).action == action


def test_deploy_model_access_default_on_with_opt_out():
    p = _build_parser()
    assert p.parse_args(["deploy"]).no_model_access is False
    assert p.parse_args(["deploy", "--no-model-access"]).no_model_access is True


# --- canonical surface harmonized with the Azure `chkpmcpaz` tool ------------
def test_canonical_chat_status_doctor_parse():
    p = _build_parser()
    assert p.parse_args(["chat", "q"]).task == "q"
    assert p.parse_args(["chat"]).task is None            # bare chat -> examples
    assert p.parse_args(["status", "--guardrail"]).guardrail is True
    assert p.parse_args(["doctor"]).cmd == "doctor"       # doctor takes no extra args


def test_chat_shares_every_agent_option():
    p = _build_parser()
    a = p.parse_args(["chat", "how many hosts?", "--runtime", "agentcore",
                      "--guardrail", "--model", "m", "--session", "s", "--actor", "x"])
    assert a.task == "how many hosts?"
    assert a.runtime == "agentcore" and a.guardrail is True
    assert a.model == "m" and a.session == "s" and a.actor == "x"


def test_deprecated_aliases_still_parse():
    p = _build_parser()
    # aliases route through the SAME arg builders, so they parse identically
    assert p.parse_args(["agent", "q"]).task == "q"
    assert p.parse_args(["verify", "--guardrail"]).guardrail is True


def test_aliases_registered_but_absent_from_command_list():
    p = _build_parser()
    sp = _subparsers_action(p)
    # the aliases are still dispatchable (present in the name->parser map)...
    assert "agent" in sp._name_parser_map
    assert "verify" in sp._name_parser_map
    # ...but the canonical verbs are what's advertised
    for canonical in ("deploy", "chat", "status", "doctor"):
        assert canonical in sp._name_parser_map


def test_help_surface_matches_azure_and_hides_aliases():
    help_text = _build_parser().format_help()
    # canonical command list (identical to the Azure tool's surface)
    assert ("{deploy,chat,status,doctor,refresh,creds,models,bridge,guardrail,"
            "destroy}") in help_text
    # the aliases must NOT be advertised as their own command rows (guard
    # against a future refactor re-exposing them, e.g. via help=SUPPRESS which
    # argparse renders literally as "==SUPPRESS==")
    def _is_command_row(line, name):
        stripped = line.strip()
        return stripped.split()[:1] == [name] if stripped else False
    rows = help_text.splitlines()
    assert not any(_is_command_row(ln, "agent") for ln in rows)
    assert not any(_is_command_row(ln, "verify") for ln in rows)
    assert "==SUPPRESS==" not in help_text


def test_alias_agent_dispatches_to_chat_handler(monkeypatch, capsys):
    import chkpmcpaws.cli as cli
    from chkpmcpaws import agent as agent_mod

    seen = {}

    def _fake_run(cfg, session, task, **kw):
        seen["task"] = task
        seen["kw"] = kw
        return 0

    monkeypatch.setattr(agent_mod, "run", _fake_run)
    monkeypatch.setattr(cli, "make_session", lambda *a, **k: object())
    rc = cli.main(["agent", "how many hosts?"])
    err = capsys.readouterr().err
    assert rc == 0
    assert seen["task"] == "how many hosts?"        # same handler as `chat`
    assert "`agent` is now `chat`" in err           # quiet stderr note


def test_alias_verify_dispatches_to_status_handler(monkeypatch, capsys):
    import chkpmcpaws.cli as cli
    from chkpmcpaws import verify as verify_mod

    seen = {}

    def _fake_verify(cfg, session, guardrail=False):
        seen["guardrail"] = guardrail
        return 0

    monkeypatch.setattr(verify_mod, "verify", _fake_verify)
    monkeypatch.setattr(cli, "make_session", lambda *a, **k: object())
    rc = cli.main(["verify", "--guardrail"])
    err = capsys.readouterr().err
    assert rc == 0
    assert seen["guardrail"] is True                # same handler as `status`
    assert "`verify` is now `status`" in err


def test_doctor_dispatches_to_read_only_module(monkeypatch):
    import chkpmcpaws.cli as cli
    from chkpmcpaws import doctor as doctor_mod

    seen = {}

    def _fake_run_doctor(cfg, session):
        seen["called"] = True
        return 0

    monkeypatch.setattr(doctor_mod, "run_doctor", _fake_run_doctor)
    monkeypatch.setattr(cli, "make_session", lambda *a, **k: object())
    assert cli.main(["doctor"]) == 0
    assert seen.get("called") is True


# --- last-resort credential guard (expired `aws login` session etc.) ---------
def test_credential_error_shapes_are_caught():
    from chkpmcpaws.cli import _is_credential_error
    from botocore.exceptions import (
        ClientError, LoginRefreshRequired, NoCredentialsError,
    )
    # the live-observed case: aws login refresh token expired (SSM call)
    assert _is_credential_error(LoginRefreshRequired()) is True
    assert _is_credential_error(NoCredentialsError()) is True
    assert _is_credential_error(ClientError(
        {"Error": {"Code": "ExpiredTokenException", "Message": "x"}}, "GetParameter")) is True
    # but real errors must NOT be swallowed
    assert _is_credential_error(ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "x"}}, "GetParameter")) is False
    assert _is_credential_error(ValueError("boom")) is False


def test_main_reports_expired_session_without_traceback(monkeypatch, capsys):
    import chkpmcpaws.cli as cli
    from botocore.exceptions import LoginRefreshRequired
    def _boom(argv=None):
        raise LoginRefreshRequired()
    monkeypatch.setattr(cli, "_main", _boom)
    rc = cli.main(["models", "status"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "expired" in out.lower() and "re-run" in out.lower()
    assert "Traceback" not in out


def test_main_does_not_swallow_real_bugs(monkeypatch):
    import pytest
    import chkpmcpaws.cli as cli
    def _boom(argv=None):
        raise ValueError("real bug")
    monkeypatch.setattr(cli, "_main", _boom)
    with pytest.raises(ValueError):
        cli.main(["verify"])
