import json

import pytest

from rastro import cli

# Captured before the autouse fixture below can patch it, so the dedicated test for
# _is_root's fail-closed behavior can call the real implementation.
_real_is_root = cli._is_root


@pytest.fixture(autouse=True)
def _pretend_root(monkeypatch):
    monkeypatch.setattr(cli, "_is_root", lambda: True)


def test_refuses_to_run_without_root(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_is_root", lambda: False)
    code = cli.main(["10.0.0.5"])
    assert code == cli.EXIT_MISSING_TOOL
    assert "sudo" in capsys.readouterr().err.lower()


def test_missing_geteuid_is_treated_as_not_root(monkeypatch):
    # A platform where privilege cannot be verified must fail closed, never assume root.
    # The autouse fixture above patches cli._is_root itself for every test in this
    # module, so it must be restored to the real implementation to exercise it here.
    monkeypatch.setattr(cli, "_is_root", _real_is_root)
    monkeypatch.delattr(cli.os, "geteuid", raising=False)
    assert cli._is_root() is False


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


def test_existing_output_dir_exits_cleanly_not_with_a_traceback(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "resolve_target", lambda t: "10.0.0.5")
    existing = tmp_path / "already"
    existing.mkdir()
    code = cli.main(["10.0.0.5", "--output", str(existing), "--no-install"])
    assert code == cli.EXIT_MISSING_TOOL
    assert "already exists" in capsys.readouterr().err


def test_failed_install_is_not_reported_as_installed(tmp_path, monkeypatch):
    from rastro.model import Artifact

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "resolve_target", lambda t: "10.0.0.5")
    # nmap present so the run proceeds; gobuster missing before AND after the install.
    monkeypatch.setattr(cli.tools, "detect",
                        lambda rules: {"nmap": "/usr/bin/nmap", "gobuster": None})
    monkeypatch.setattr(cli.deps, "detect_manager", lambda: "apt")
    monkeypatch.setattr(cli.deps, "plan_installs", lambda d, t, m: (["gobuster"], []))
    monkeypatch.setattr(
        cli.deps, "install",
        lambda m, p, *, output_dir: Artifact(tool="apt", command="apt-get install -y gobuster",
                                             exit_code=100, stdout_path=""),
    )
    for stage in (cli.discover, cli.identify, cli.enumerate_stage, cli.classify):
        monkeypatch.setattr(stage, "run", lambda host, ctx: host)

    code = cli.main(["10.0.0.5"])
    result = json.loads(next(tmp_path.glob("rastro-*/result.json")).read_text())
    assert result["installed"] == []                      # nothing actually appeared
    assert any(a["exit_code"] == 100 for a in result["artifacts"])   # but the attempt is recorded
    assert code == cli.EXIT_PARTIAL                        # failed artifact => partial


def test_failed_enumeration_exits_partial(tmp_path, monkeypatch):
    from rastro.model import Artifact, Port

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "resolve_target", lambda t: "10.0.0.5")
    monkeypatch.setattr(cli.tools, "detect", lambda rules: {"nmap": "/usr/bin/nmap"})

    def fake_discover(host, ctx):
        host.ports.append(
            Port(number=445,
                 artifacts=[Artifact(tool="nmap", command="x", exit_code=1, stdout_path="")])
        )
        return host

    monkeypatch.setattr(cli.discover, "run", fake_discover)
    for stage in (cli.identify, cli.enumerate_stage, cli.classify):
        monkeypatch.setattr(stage, "run", lambda host, ctx: host)

    assert cli.main(["10.0.0.5", "--no-install"]) == cli.EXIT_PARTIAL


def test_ownership_is_handed_back_even_when_a_stage_raises(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(cli, "resolve_target", lambda t: "10.0.0.5")
    monkeypatch.setattr(cli.tools, "detect", lambda rules: {"nmap": "/usr/bin/nmap"})

    def boom(host, ctx):
        raise RuntimeError("stage exploded")

    monkeypatch.setattr(cli.discover, "run", boom)

    called: list = []
    monkeypatch.setattr(cli, "drop_ownership", lambda path: called.append(path))

    with pytest.raises(RuntimeError):
        cli.main(["10.0.0.5", "--no-install"])
    assert called, "drop_ownership must run from the finally block"
