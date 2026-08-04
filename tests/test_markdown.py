from rastro.model import Artifact, Finding, Host, Port, Service
from rastro.render.markdown import render


def _host():
    host = Host(target="10.0.0.5", resolved_ip="10.0.0.5", started_at="2026-08-04T12:00:00Z")
    host.ports = [
        Port(number=445, service=Service(name="smb", product="Samba", confidence="confirmed"),
             artifacts=[Artifact(tool="nmap", command="nmap -p445", stdout_path="raw/445.txt")])
    ]
    host.findings = [
        Finding(id="smb-signing-disabled", title="SMB signing not required", interest="high",
                evidence="message_signing: disabled", source_artifact="raw/445.txt")
    ]
    host.buckets = {"other": [445]}
    host.skipped = [{"tool": "gobuster", "reason": "not installed",
                     "would_have_run": ["gobuster dir -u http://10.0.0.5/"]}]
    return host


def test_report_includes_target_and_ports():
    out = render(_host())
    assert "10.0.0.5" in out
    assert "445" in out


def test_report_shows_findings_with_evidence():
    out = render(_host())
    assert "SMB signing not required" in out
    assert "message_signing: disabled" in out
    assert "raw/445.txt" in out


def test_report_always_surfaces_what_was_skipped():
    # A clean report that was clean only because a tool was missing is a lie.
    out = render(_host())
    assert "gobuster" in out
    assert "not installed" in out


def test_empty_host_renders_without_error():
    out = render(Host(target="10.0.0.5"))
    assert "10.0.0.5" in out
