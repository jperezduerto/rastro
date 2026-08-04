import json

import pytest

from rastro import cli


@pytest.fixture(autouse=True)
def _pretend_root(monkeypatch):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)


def test_refuses_to_run_without_root(monkeypatch, capsys):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    code = cli.main(["10.0.0.5"])
    assert code == cli.EXIT_MISSING_TOOL
    assert "sudo" in capsys.readouterr().err.lower()


def test_schema_subcommand_emits_valid_json(capsys):
    assert cli.main(["schema"]) == cli.EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["title"] == "rastro result"
    assert "target" in payload["properties"]


def test_unresolvable_target_exits_two(monkeypatch, capsys):
    monkeypatch.setattr(cli, "resolve_target", _raise_unreachable)
    assert cli.main(["no-such-host.invalid"]) == cli.EXIT_UNREACHABLE


def _raise_unreachable(target):
    raise cli.UnreachableTarget(target)


def test_dry_run_writes_no_output_dir_and_prints_commands(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "resolve_target", lambda t: "10.0.0.5")
    code = cli.main(["10.0.0.5", "--dry-run"])
    assert code == cli.EXIT_OK
    assert list(tmp_path.iterdir()) == []
    assert "nmap" in capsys.readouterr().out


def test_missing_required_tool_exits_one(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "resolve_target", lambda t: "10.0.0.5")
    monkeypatch.setattr(cli.tools, "detect", lambda rules: {"nmap": None})
    monkeypatch.setattr(cli.deps, "detect_manager", lambda: None)
    assert cli.main(["10.0.0.5", "--no-install"]) == cli.EXIT_MISSING_TOOL
    assert "nmap" in capsys.readouterr().err


def test_output_path_is_printed_first(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "resolve_target", lambda t: "10.0.0.5")
    monkeypatch.setattr(cli.tools, "detect", lambda rules: {"nmap": "/usr/bin/nmap"})
    monkeypatch.setattr(cli.discover, "run", lambda host, ctx: host)
    cli.main(["10.0.0.5", "--no-install"])
    assert "rastro-10.0.0.5-" in capsys.readouterr().out.splitlines()[0]
