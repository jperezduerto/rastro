import re

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


def test_no_open_ports_says_so_explicitly():
    # With -Pn nmap exits 0 against a dead host, so an empty ports table alone
    # reads identically to a genuinely clean host.
    out = render(Host(target="10.0.0.5"))
    assert "No open ports found." in out


def test_run_level_commands_are_reported_with_exit_code_and_raw_path():
    # The only evidence that a sweep ran at all when it found nothing.
    host = Host(target="10.0.0.5")
    host.artifacts = [
        Artifact(tool="nmap", command="nmap -Pn -sS 10.0.0.5", exit_code=1,
                 stdout_path="raw/discover.txt")
    ]
    out = render(host)
    assert "## Run commands" in out
    assert "nmap -Pn -sS 10.0.0.5" in out
    assert "raw/discover.txt" in out
    assert "| 1 |" in out


def test_no_run_level_commands_says_so_explicitly():
    assert "No run-level commands were executed." in render(Host(target="10.0.0.5"))


def test_hostile_banner_cannot_break_out_of_a_table_cell():
    # product/version come from the scanned host's own banner. A `|` in there would
    # split the row and corrupt a report pasted into a client deliverable.
    host = Host(target="10.0.0.5")
    host.ports = [
        Port(number=80, service=Service(
            name="http", product="evil | col | injected", version="1.0 | 2.0",
            confidence="confirmed"))
    ]
    host.skipped = [{"tool": "gob|uster", "reason": "not | installed",
                     "would_have_run": ["cmd | with | pipes"]}]

    out = render(host)

    port_row = [ln for ln in out.splitlines() if ln.startswith("| 80 |")][0]
    assert _unescaped_pipes(port_row) == 5   # exactly the 4 declared columns
    assert "evil \\| col \\| injected" in port_row
    skipped_row = [ln for ln in out.splitlines() if "gob" in ln][0]
    assert _unescaped_pipes(skipped_row) == 4    # 3 declared columns


def _unescaped_pipes(row: str) -> int:
    """Count only the pipes markdown treats as column delimiters."""
    return len(re.findall(r"(?<!\\)\|", row))
