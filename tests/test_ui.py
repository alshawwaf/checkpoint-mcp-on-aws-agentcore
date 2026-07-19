"""UI reporter: color math, plain-mode opt-outs, and the log-file tee.
No TTY is required -- these exercise the non-interactive paths."""

import os
import re
from pathlib import Path

import pytest

from chkpmcpaws import awsutil, config, ui
from chkpmcpaws.config import StackConfig


def test_lerp_endpoints_and_midpoint():
    assert ui._lerp((0, 0, 0), (10, 20, 30), 0) == (0, 0, 0)
    assert ui._lerp((0, 0, 0), (10, 20, 30), 1) == (10, 20, 30)
    assert ui._lerp((0, 0, 0), (10, 20, 30), 0.5) == (5, 10, 15)


def test_plain_opt_outs(monkeypatch):
    monkeypatch.setattr(ui, "FORCE_PLAIN", False)
    monkeypatch.setenv("CHKP_UI", "plain")
    assert ui._tty_ui_wanted() is False
    monkeypatch.setenv("CHKP_UI", "tui")
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert ui._tty_ui_wanted() is True
    monkeypatch.setenv("NO_COLOR", "1")
    assert ui._tty_ui_wanted() is False


def test_force_plain_flag(monkeypatch):
    monkeypatch.delenv("CHKP_UI", raising=False)
    monkeypatch.setattr(ui, "FORCE_PLAIN", True)
    assert ui._tty_ui_wanted() is False


def test_reporter_tees_and_routes_log(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CHKP_UI", "plain")
    monkeypatch.setenv("CHKP_LOG_DIR", str(tmp_path))
    rep = ui.Reporter("deploy", "DEPLOY", ["one", "two"], "us-east-1")
    ui.activate(rep)
    rep.begin()
    awsutil.log("hello detail")          # routed through the reporter
    rep.begin("two")
    awsutil.log("second detail")
    ui.deactivate()
    # summaries may mix plain strings and (terminal_line, log_line) tuples --
    # the tuple's log side goes to the file, the terminal side to stdout.
    rep.close(ok=True, summary=[
        "DONE",
        ("\x1b[1mSTYLED-TERM\x1b[0m", "PLAIN-LOG-SIDE"),
    ])

    # log() routing is torn down after deactivate()
    assert awsutil._LOG_SINK is None
    # everything landed in the log file, verbatim
    logs = list(tmp_path.glob("chkpmcpaws-deploy-*.log"))
    assert len(logs) == 1
    body = logs[0].read_text()
    assert "hello detail" in body and "second detail" in body
    assert "[1/2] one" in body and "[2/2] two" in body
    # the tuple split: only the log side reaches the file, ANSI-free
    assert "PLAIN-LOG-SIDE" in body
    assert "STYLED-TERM" not in body
    assert "\x1b" not in body
    # plain mode also printed to stdout -- terminal sides included
    out = capsys.readouterr().out
    assert "hello detail" in out and "DONE" in out
    assert "STYLED-TERM" in out
    assert "PLAIN-LOG-SIDE" not in out


def test_log_path_migrates_legacy_chkpmcp_logs(tmp_path, monkeypatch):
    # the tool rename moved the default log dir ~/.chkpmcp -> ~/.chkpmcpaws;
    # transcripts (the audit trail for past stack operations) must follow.
    monkeypatch.delenv("CHKP_LOG_DIR", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    legacy = tmp_path / ".chkpmcp" / "logs"
    legacy.mkdir(parents=True)
    (legacy / "chkpmcp-deploy-20250101-000000.log").write_text("old transcript")
    path = ui._log_path("verify")
    new_dir = tmp_path / ".chkpmcpaws" / "logs"
    assert os.path.dirname(path) == str(new_dir)
    moved = new_dir / "chkpmcp-deploy-20250101-000000.log"
    assert moved.read_text() == "old transcript"
    # the emptied legacy dir is removed, so the migration self-retires
    assert not (tmp_path / ".chkpmcp").exists()


def test_log_path_custom_log_dir_leaves_legacy_logs_alone(tmp_path, monkeypatch):
    # CHKP_LOG_DIR means the operator owns the location -- no migration.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CHKP_LOG_DIR", str(tmp_path / "custom"))
    legacy = tmp_path / ".chkpmcp" / "logs"
    legacy.mkdir(parents=True)
    (legacy / "old.log").write_text("x")
    path = ui._log_path("deploy")
    assert os.path.dirname(path) == str(tmp_path / "custom")
    assert (legacy / "old.log").read_text() == "x"


def test_stack_up_banner_variants():
    assert isinstance(ui.stack_up_banner(ok=True), str)
    assert "INCOMPLETE" in ui.stack_up_banner(ok=False)
    assert "PARTIAL" in ui.stack_up_banner(ok=True, partial=True)


# ---------------------------------------------------------------- fixtures --
# Repo-specific inputs for the mirrored links-block tests below (the Azure
# sibling builds the same fixtures from portal_links / portal_links_lines).
_ACCT = "123456789012"
_GW_ID = "chkp-mcp-gw-abc123"
_POOL_ID = "us-east-1_Ab1Cd2Ef3"
_TITLE = "Open in the AWS Console:"
_REGION = "us-east-1"
_TTY_ENV = {"TERM": "xterm-256color"}


def _links():
    return config.console_links(StackConfig(), _ACCT, gateway_id=_GW_ID,
                                pool_id=_POOL_ID)


def _plain_lines():
    return config.console_links_lines(StackConfig(), _ACCT, gateway_id=_GW_ID,
                                      pool_id=_POOL_ID)


# =============================================================================
# Links block -- tier detection, pure helpers, per-tier rendering invariants,
# and the close() terminal/log split. Everything below this marker is
# MIRRORED byte-identical with the sibling repo's tests/test_ui.py
# (chkpmcpaws <-> chkpmcpaz); only the fixtures above it (_links /
# _plain_lines / _TITLE / _REGION / _TTY_ENV) differ. Keep it that way:
# fix a test in one repo, copy the section to the other.
# =============================================================================


# ------------------------------------------------------------ tier chooser --
def test_links_render_tier_force_plain_wins():
    env = dict(_TTY_ENV, TERM_PROGRAM="iTerm.app")
    assert ui.links_render_tier(True, env, True) == ui.TIER_PLAIN


@pytest.mark.parametrize("isatty,env", [
    (True, dict(_TTY_ENV, NO_COLOR="1", TERM_PROGRAM="iTerm.app")),
    (True, dict(_TTY_ENV, CHKP_UI="plain", TERM_PROGRAM="iTerm.app")),
    (False, dict(_TTY_ENV, TERM_PROGRAM="iTerm.app")),        # piped
    (True, {"TERM": ""}),
    (True, {"TERM": "dumb"}),
    (True, {}),                                               # TERM unset
])
def test_links_render_tier_plain_optouts(isatty, env):
    assert ui.links_render_tier(isatty, env, False) == ui.TIER_PLAIN


@pytest.mark.parametrize("extra", [
    {"TERM_PROGRAM": "iTerm.app"},
    {"TERM_PROGRAM": "WezTerm"},
    {"TERM_PROGRAM": "vscode"},
    {"TERM_PROGRAM": "ghostty"},
    {"WT_SESSION": "x"},
    {"KITTY_WINDOW_ID": "1"},
])
def test_links_render_tier_fancy_on_osc8_terminals(extra):
    env = dict(_TTY_ENV, **extra)
    assert ui.links_render_tier(True, env, False) == ui.TIER_FANCY


def test_links_render_tier_apple_terminal_is_basic_not_fancy():
    # Terminal.app auto-linkifies plain URLs but does NOT render OSC 8.
    env = dict(_TTY_ENV, TERM_PROGRAM="Apple_Terminal")
    assert ui.links_render_tier(True, env, False) == ui.TIER_BASIC


def test_links_render_tier_basic_without_osc8_markers():
    assert ui.links_render_tier(True, dict(_TTY_ENV), False) == ui.TIER_BASIC


# --------------------------------------------------------- small pure bits --
def test_osc8_assembly():
    assert ui.osc8("https://x", "t") == "\x1b]8;;https://x\x1b\\t\x1b]8;;\x1b\\"


def test_wrap_url_math():
    assert ui.wrap_url("abcdef", 4) == ["abcd", "ef"]
    assert ui.wrap_url("abc", 10) == ["abc"]                 # width >= len
    assert ui.wrap_url("", 10) == []                         # never ['']
    assert ui.wrap_url("abcd", 0) == ["a", "b", "c", "d"]    # width guard -> 1
    assert ui.wrap_url("abcd", -3) == ["a", "b", "c", "d"]


def test_strip_ansi_and_visible_len():
    styled = ui.BOLD + ui.ULINE + "\x1b[38;2;255;45;149m" + "hi" + ui.RESET
    assert ui.strip_ansi(styled) == "hi"
    assert ui.strip_ansi(ui.osc8("https://x", "text")) == "text"             # ST
    assert ui.strip_ansi("\x1b]8;;https://x\x07text\x1b]8;;\x07") == "text"  # BEL
    assert ui.strip_ansi("plain • text") == "plain • text"   # idempotent
    mixed = ui.ULINE + "u" + ui.RESET + ui.osc8("https://x", "rl")
    assert ui.strip_ansi(ui.strip_ansi(mixed)) == ui.strip_ansi(mixed) == "url"
    assert ui.visible_len(styled) == 2
    assert ui.visible_len(ui.osc8("https://very/long/url", "ab")) == 2
    # DOTALL: an OSC payload spanning a newline still strips
    assert ui.strip_ansi("\x1b]8;;https://x\ny\x1b\\t\x1b]8;;\x1b\\") == "t"


# ------------------------------------------------------------- links_block --
def _term_lines(pairs):
    """Flatten the terminal sides (a tuple may fold several visual lines)."""
    return [ln for term, _ in pairs for ln in term.split("\n")]


def _log_lines(pairs):
    return [ln for _, log in pairs for ln in log.split("\n")]


def test_links_block_empty_renders_nothing():
    for tier in (ui.TIER_PLAIN, ui.TIER_BASIC, ui.TIER_FANCY):
        assert ui.links_block([], title=_TITLE, tier=tier) == []


def test_links_block_plain_tier_byte_identical_to_lines_helper():
    # REGRESSION PIN: --plain / piped / CI output must never change shape.
    pairs = ui.links_block(_links(), title=_TITLE, tier=ui.TIER_PLAIN)
    assert [term for term, _ in pairs] == _plain_lines()
    for term, log in pairs:
        assert term == log


@pytest.mark.parametrize("tier", [ui.TIER_FANCY, ui.TIER_BASIC, ui.TIER_PLAIN])
def test_links_block_log_side_is_always_plain(tier):
    pairs = ui.links_block(_links(), title=_TITLE, tier=tier, width=100)
    for _, log in pairs:
        assert "\x1b" not in log
    assert _log_lines(pairs) == _plain_lines()


def test_links_block_basic_tier_keeps_urls_intact():
    links = _links()
    pairs = ui.links_block(links, title=_TITLE, tier=ui.TIER_BASIC)
    lines = _term_lines(pairs)
    for _, url in links:
        hits = [ln for ln in lines if url in ln]   # contiguous, escapes outside
        assert hits, f"URL not intact in basic tier: {url}"
        # escapes sit only OUTSIDE the URL: stripping leaves the bare URL
        assert any(ui.strip_ansi(ln).strip() == url for ln in hits)
    for ln in lines:
        assert "\x1b]8;;" not in ln                # no OSC 8 in the basic tier
    assert any(ui.BOLD in ln for ln in lines)      # title/labels are styled


_OSC8_LINK = re.compile(r"\x1b]8;;(.*?)\x1b\\(.*?)\x1b]8;;\x1b\\", re.DOTALL)


def test_links_block_fancy_tier_clickability_invariant():
    # CLICKABILITY IS SACRED: a hard-wrapped URL fragment may only ever appear
    # as the text of a complete OSC 8 hyperlink carrying its full target.
    links = _links()
    urls = {u for _, u in links}
    windows = {u[i:i + 12] for u in urls for i in range(len(u) - 11)}
    pairs = ui.links_block(links, title=_TITLE, tier=ui.TIER_FANCY, width=80)
    seen = {}
    for ln in _term_lines(pairs):
        for target, text in _OSC8_LINK.findall(ln):
            visible = ui.strip_ansi(text)
            assert visible in target               # fragment of its own target
            seen.setdefault(target, []).append(visible)
        # outside the OSC 8 wrappers no URL text ever appears: a bare
        # hard-wrapped fragment would be unclickable in every terminal
        remainder = ui.strip_ansi(_OSC8_LINK.sub("", ln))
        assert not any(w in remainder for w in windows)
    # every link renders, and its fragments reassemble the full URL in order
    for _, url in links:
        assert "".join(seen[url]) == url


@pytest.mark.parametrize("width", [60, 120])       # the default floor and cap
def test_links_block_fancy_width_and_alignment(width):
    links = _links() + [("Over-long", "https://example.com/" + "a" * 180)]
    pairs = ui.links_block(links, title=_TITLE, tier=ui.TIER_FANCY, width=width)
    box = [ln for ln in _term_lines(pairs) if ln.strip()]
    widths = {ui.visible_len(ln) for ln in box}
    assert all(w <= width for w in widths)
    assert len(widths) == 1                        # borders align


def test_links_block_default_tier_is_plain_when_not_a_tty(monkeypatch):
    # unit tests run piped: sys.stdout is not a tty -> the default tier is
    # PLAIN even without any explicit opt-out
    monkeypatch.setattr(ui, "FORCE_PLAIN", False, raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("CHKP_UI", raising=False)
    pairs = ui.links_block(_links(), title=_TITLE)
    assert [term for term, _ in pairs] == _plain_lines()


# ----------------------------------------------- close() terminal/log split --
def _plain_reporter(monkeypatch, tmp_path):
    monkeypatch.setattr(ui, "FORCE_PLAIN", False, raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("CHKP_UI", "plain")
    monkeypatch.setenv("CHKP_LOG_DIR", str(tmp_path))
    return ui.Reporter("linkstest", "TEST", ["step one"], _REGION)


def test_close_tees_log_side_and_prints_term_side(monkeypatch, tmp_path, capsys):
    rep = _plain_reporter(monkeypatch, tmp_path)
    rep.begin()
    rep.detail("hello")
    rep.close(ok=True, summary=[
        "plain summary line",
        ("\x1b[1mSTYLED for terminal\x1b[0m", "  clean for the log"),
    ])
    out = capsys.readouterr().out
    assert "plain summary line" in out
    assert "\x1b[1mSTYLED for terminal\x1b[0m" in out       # term side printed
    assert "clean for the log" not in out                   # log side not printed
    log = Path(rep.log_path).read_text(encoding="utf-8")
    assert "plain summary line" in log
    assert "  clean for the log" in log                     # log side tee'd
    assert "STYLED for terminal" not in log
    assert "\x1b" not in log                                # log is escape-free
    assert "hello" in log                                   # details still tee'd


def test_close_strips_ansi_banner_from_log(monkeypatch, tmp_path, capsys):
    # documents the deliberate fix: the styled gradient banner used to leak
    # raw ANSI into the log; _tee now strips escapes (visible text verbatim)
    monkeypatch.setattr(ui, "FORCE_PLAIN", False, raising=False)
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("CHKP_UI", "tui")           # force the styled banner
    banner = ui.stack_up_banner(ok=True)
    assert "\x1b" in banner                        # the banner IS styled
    rep = _plain_reporter(monkeypatch, tmp_path)   # flips CHKP_UI back to plain
    rep.close(ok=True, summary=[banner])
    capsys.readouterr()
    log = Path(rep.log_path).read_text(encoding="utf-8")
    assert "\x1b" not in log
    assert "STACK UP" in log


def test_close_log_matches_plain_stdout_for_links_block(monkeypatch, tmp_path, capsys):
    # End-to-end: a fancy links block in the summary still lands PLAIN in the
    # log -- byte-identical to the *_links_lines helper output.
    rep = _plain_reporter(monkeypatch, tmp_path)
    rep.close(ok=True, summary=ui.links_block(_links(), title=_TITLE,
                                              tier=ui.TIER_FANCY, width=100))
    out = capsys.readouterr().out
    assert "\x1b]8;;" in out                       # terminal got OSC 8
    log = Path(rep.log_path).read_text(encoding="utf-8")
    assert "\x1b" not in log
    for line in _plain_lines():
        if line:
            assert line in log.splitlines()
