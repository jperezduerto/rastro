from rastro.model import Context, Host, Port, Service
from rastro.stages.enumerate import run

RULES = {
    "version": 1,
    "services": {
        "smb": {
            "ports": [445],
            "enum": [
                {"id": "echo-shares", "tool": "echo", "command": "echo shares-for {target}",
                 "timeout": 10, "requires_confidence": "guess"},
            ],
        }
    },
}


def _host_with_smb():
    host = Host(target="10.0.0.5")
    host.ports = [Port(number=445, service=Service(name="smb", confidence="guess"))]
    return host


def test_artifacts_attach_to_the_originating_port(tmp_path):
    ctx = Context(target="10.0.0.5", output_dir=tmp_path, rules=RULES,
                  tools={"echo": "/bin/echo"})
    result = run(_host_with_smb(), ctx)
    assert len(result.ports[0].artifacts) == 1
    assert result.ports[0].artifacts[0].tool == "echo"


def test_output_is_written_and_readable(tmp_path):
    ctx = Context(target="10.0.0.5", output_dir=tmp_path, rules=RULES,
                  tools={"echo": "/bin/echo"})
    result = run(_host_with_smb(), ctx)
    written = (tmp_path / result.ports[0].artifacts[0].stdout_path).read_text()
    assert "shares-for" in written


def test_dry_run_executes_nothing_but_records_the_plan(tmp_path):
    ctx = Context(target="10.0.0.5", output_dir=tmp_path, rules=RULES,
                  tools={"echo": "/bin/echo"}, dry_run=True)
    result = run(_host_with_smb(), ctx)
    assert result.ports[0].artifacts == []
    assert not (tmp_path / "raw").exists()
    assert any("echo shares-for" in s["would_have_run"][0] for s in result.skipped)


def test_skips_from_planning_land_on_the_host(tmp_path):
    ctx = Context(target="10.0.0.5", output_dir=tmp_path, rules=RULES, tools={"echo": None})
    result = run(_host_with_smb(), ctx)
    assert [s["tool"] for s in result.skipped] == ["echo"]
    assert result.ports[0].artifacts == []
