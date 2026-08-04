from pathlib import Path

from rastro.stages.discover import (
    parse_nmap_open_ports,
    parse_rustscan_ports,
    sweep_command,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_parses_only_open_ports_from_nmap():
    ports = parse_nmap_open_ports((FIXTURES / "nmap_open_ports.txt").read_text())
    assert ports == [22, 80, 445, 5985]        # 3389 is closed, must be excluded


def test_parses_rustscan_greppable():
    ports = parse_rustscan_ports((FIXTURES / "rustscan_greppable.txt").read_text())
    assert ports == [22, 80, 445, 5985]


def test_parsers_return_empty_on_garbage():
    assert parse_nmap_open_ports("no ports here") == []
    assert parse_rustscan_ports("") == []


def test_sweep_prefers_rustscan_when_present():
    cmd, tool = sweep_command("10.0.0.5", {"rustscan": "/usr/bin/rustscan", "nmap": "/usr/bin/nmap"})
    assert tool == "rustscan"
    assert "10.0.0.5" in cmd


def test_sweep_falls_back_to_nmap():
    cmd, tool = sweep_command("10.0.0.5", {"rustscan": None, "nmap": "/usr/bin/nmap"})
    assert tool == "nmap"
    assert "-sS" in cmd                        # root-only SYN scan; rastro always has root


def test_sweep_quotes_the_target():
    cmd, _ = sweep_command("10.0.0.5; rm -rf /", {"rustscan": None, "nmap": "/usr/bin/nmap"})
    assert "; rm -rf /" not in cmd.replace("'10.0.0.5; rm -rf /'", "")
