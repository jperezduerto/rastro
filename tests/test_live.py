import io

from rastro.model import Artifact, Finding, Host, Port, Service
from rastro.render.live import Reporter, interesting_lines, supports_color


def _reporter(color=False):
    stream = io.StringIO()
    return Reporter(quiet=False, color=color, stream=stream), stream


def test_color_is_disabled_when_no_color_is_set(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert supports_color(io.StringIO()) is False


def test_color_is_disabled_on_a_non_tty(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert supports_color(io.StringIO()) is False   # StringIO is not a terminal


def test_quiet_reporter_writes_nothing():
    stream = io.StringIO()
    reporter = Reporter(quiet=True, color=True, stream=stream)
    reporter.banner("10.0.0.5", "/tmp/out")
    reporter.command("nmap -sS 10.0.0.5")
    reporter.summary(Host(target="10.0.0.5"))
    assert stream.getvalue() == ""


def test_every_command_is_shown_before_its_result():
    reporter, stream = _reporter()
    reporter.command("nmap -sS 10.0.0.5")
    reporter.result(0, 1.25, False, ["22/tcp open ssh"])
    out = stream.getvalue()
    assert "nmap -sS 10.0.0.5" in out
    assert "ok" in out and "1.2s" in out
    assert "22/tcp open ssh" in out


def test_failure_and_timeout_are_distinguishable():
    reporter, stream = _reporter()
    reporter.result(1, 0.5, False)
    reporter.result(124, 60.0, True)
    out = stream.getvalue()
    assert "exit 1" in out
    assert "timeout" in out


def test_color_codes_appear_only_when_color_is_on():
    plain, plain_stream = _reporter(color=False)
    plain.stage("discover", "sweeping")
    assert "\033[" not in plain_stream.getvalue()

    fancy, fancy_stream = _reporter(color=True)
    fancy.stage("discover", "sweeping")
    assert "\033[" in fancy_stream.getvalue()


def test_interesting_lines_prefers_signal_over_banner_noise():
    text = (
        "Starting Nmap 7.99 ( https://nmap.org )\n"
        "Nmap scan report for 10.0.0.5\n"
        "Host is up (0.001s latency).\n"
        "22/tcp open ssh OpenSSH 9.6\n"
        "445/tcp open microsoft-ds\n"
        "|_ smb2-security-mode: Message signing enabled but not required\n"
        "Nmap done: 1 IP address\n"
    )
    picked = interesting_lines(text)
    assert any("22/tcp open" in line for line in picked)
    assert any("smb2-security-mode" in line for line in picked)
    assert not any("Starting Nmap" in line for line in picked)


def test_interesting_lines_falls_back_for_unrecognised_output():
    picked = interesting_lines("some tool said something\nand another thing\n")
    assert picked == ["some tool said something", "and another thing"]


def test_summary_lists_ports_services_findings_and_warnings():
    host = Host(target="10.0.0.5")
    host.ports = [
        Port(number=445, service=Service(name="smb", product="Samba", confidence="confirmed"),
             artifacts=[Artifact(tool="nxc", command="nxc", exit_code=1)]),
        Port(number=80, service=Service(name="http", confidence="guess")),
    ]
    host.buckets = {"web": [80], "other": [445]}
    host.findings = [Finding(id="smb-signing-disabled", title="SMB signing not required",
                             interest="high", evidence="not required", port=445)]
    host.skipped = [{"tool": "gobuster", "reason": "not installed", "would_have_run": ["x"]}]

    reporter, stream = _reporter()
    reporter.summary(host)
    out = stream.getvalue()

    assert "SUMMARY" in out and "10.0.0.5" in out
    assert "445" in out and "smb" in out and "Samba" in out and "confirmed" in out
    assert "80" in out and "guess" in out
    assert "web" in out
    assert "SMB signing not required" in out
    assert "1 command(s) failed" in out
    assert "1 step(s) not run" in out


def test_summary_says_so_when_nothing_was_found():
    reporter, stream = _reporter()
    reporter.summary(Host(target="10.0.0.5"))
    out = stream.getvalue()
    assert "no open ports found" in out
    assert "Findings: none" in out
