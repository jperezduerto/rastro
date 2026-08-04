from rastro.model import Context, Host, Port
from rastro.rules.loader import load_services
from rastro.stages.identify import HTTP_HINT_PORTS, run, svc_for_port

RULES = load_services()


def test_known_port_maps_to_service():
    assert svc_for_port(445, RULES) == "smb"
    assert svc_for_port(22, RULES) == "ssh"


def test_http_hint_port_maps_to_http():
    assert svc_for_port(8090, RULES) == "http"
    assert 8090 in HTTP_HINT_PORTS


def test_unknown_port_returns_empty():
    assert svc_for_port(64999, RULES) == ""


def test_run_assigns_guess_confidence_from_port_map(tmp_path):
    host = Host(target="10.0.0.5")
    host.ports = [Port(number=445), Port(number=64999)]
    ctx = Context(target="10.0.0.5", output_dir=tmp_path, rules=RULES, dry_run=True)

    result = run(host, ctx)

    assert result.ports[0].service.name == "smb"
    assert result.ports[0].service.confidence == "guess"
    assert result.ports[1].service is None      # unknown ports get no service


def test_run_is_idempotent(tmp_path):
    host = Host(target="10.0.0.5")
    host.ports = [Port(number=445)]
    ctx = Context(target="10.0.0.5", output_dir=tmp_path, rules=RULES, dry_run=True)
    once = run(host, ctx)
    twice = run(once, ctx)
    assert twice.ports[0].service.name == "smb"
    assert len(twice.ports) == 1


def test_version_probe_command_covers_all_ports_and_quotes_target():
    from rastro.stages.identify import version_probe_command

    cmd = version_probe_command("10.0.0.5", [22, 445])
    assert "-sV" in cmd
    assert "-p22,445" in cmd
    assert "'10.0.0.5'" in cmd


def test_parse_nmap_service_extracts_product_and_version():
    from rastro.stages.identify import parse_nmap_service

    text = "445/tcp open  microsoft-ds Samba smbd 4.6.2\n"
    product, version = parse_nmap_service(text, 445)
    assert "Samba" in product
    assert version == "4.6.2"


def test_parse_nmap_service_returns_empty_when_absent():
    from rastro.stages.identify import parse_nmap_service

    assert parse_nmap_service("nothing here", 445) == ("", "")


def test_version_probe_upgrades_confidence_to_confirmed(tmp_path, monkeypatch):
    # Without this upgrade every `requires_confidence: confirmed` rule is dead code.
    import rastro.stages.identify as identify_module
    from rastro.model import Artifact

    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "identify.txt").write_text("445/tcp open  microsoft-ds Samba smbd 4.6.2\n")

    monkeypatch.setattr(
        identify_module,
        "run_command",
        lambda *a, **k: Artifact(tool="nmap", command="nmap -sV",
                                 stdout_path="raw/identify.txt"),
    )

    host = Host(target="10.0.0.5")
    host.ports = [Port(number=445)]
    ctx = Context(target="10.0.0.5", output_dir=tmp_path, rules=RULES, dry_run=False)

    result = run(host, ctx)

    assert result.ports[0].service.confidence == "confirmed"
    assert result.ports[0].service.version == "4.6.2"


def test_dry_run_stays_at_guess_and_runs_no_command(tmp_path, monkeypatch):
    import rastro.stages.identify as identify_module

    def _explode(*a, **k):
        raise AssertionError("dry-run must not execute commands")

    monkeypatch.setattr(identify_module, "run_command", _explode)

    host = Host(target="10.0.0.5")
    host.ports = [Port(number=445)]
    ctx = Context(target="10.0.0.5", output_dir=tmp_path, rules=RULES, dry_run=True)

    result = run(host, ctx)
    assert result.ports[0].service.confidence == "guess"
