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


def test_version_probe_command_covers_all_ports():
    from rastro.stages.identify import version_probe_command

    cmd = version_probe_command("10.0.0.5", [22, 445])
    assert "-sV" in cmd
    assert "-p22,445" in cmd
    assert cmd.endswith("10.0.0.5")


def test_version_probe_command_neutralises_injection():
    # shlex.quote leaves a safe token bare, so assert the security property
    # (the metacharacters cannot escape the argument), not a literal quote char.
    import shlex

    from rastro.stages.identify import version_probe_command

    hostile = "10.0.0.5; rm -rf /"
    cmd = version_probe_command(hostile, [22])
    assert shlex.quote(hostile) in cmd
    assert "; rm -rf /" not in cmd.replace(shlex.quote(hostile), "")


def test_parse_nmap_service_extracts_product_and_version():
    from rastro.stages.identify import parse_nmap_service

    text = "445/tcp open  microsoft-ds Samba smbd 4.6.2\n"
    product, version = parse_nmap_service(text, 445)
    assert "Samba" in product
    assert version == "4.6.2"


def test_parse_nmap_service_returns_empty_when_absent():
    from rastro.stages.identify import parse_nmap_service

    assert parse_nmap_service("nothing here", 445) == ("", "")


def test_parse_nmap_service_handles_letter_suffixed_version():
    from rastro.stages.identify import parse_nmap_service

    text = "22/tcp open  ssh  OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)\n"
    product, version = parse_nmap_service(text, 22)
    assert product == "OpenSSH"
    assert version == "8.2p1"          # not 2.0 from the protocol parenthetical


def test_parse_nmap_service_does_not_truncate_or_leak_fragments():
    from rastro.stages.identify import parse_nmap_service

    product, version = parse_nmap_service("21/tcp open  ftp  ProFTPD 1.3.5e\n", 21)
    assert product == "ProFTPD"
    assert version == "1.3.5e"


def test_parse_nmap_service_keeps_digits_inside_the_product_name():
    from rastro.stages.identify import parse_nmap_service

    product, version = parse_nmap_service("80/tcp open  http  Product2.0Server 2.0\n", 80)
    assert product == "Product2.0Server"
    assert version == "2.0"


def test_parse_nmap_service_handles_a_versionless_banner():
    from rastro.stages.identify import parse_nmap_service

    product, version = parse_nmap_service("135/tcp open  msrpc  Microsoft Windows RPC\n", 135)
    assert product == "Microsoft Windows RPC"
    assert version == ""


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
