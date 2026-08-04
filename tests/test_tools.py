from rastro import tools


def test_detect_reports_path_when_binary_exists(monkeypatch):
    monkeypatch.setattr(tools.shutil, "which", lambda b: "/usr/bin/nmap" if b == "nmap" else None)
    detected = tools.detect({"nmap": {"binaries": ["nmap"], "required": True, "packages": {}}})
    assert detected["nmap"] == "/usr/bin/nmap"


def test_detect_reports_none_when_absent(monkeypatch):
    monkeypatch.setattr(tools.shutil, "which", lambda b: None)
    detected = tools.detect({"gobuster": {"binaries": ["gobuster"], "required": False, "packages": {}}})
    assert detected["gobuster"] is None


def test_detect_accepts_any_alias_binary(monkeypatch):
    # netexec ships as `nxc` on newer builds and `netexec` on older ones.
    monkeypatch.setattr(tools.shutil, "which", lambda b: "/usr/bin/nxc" if b == "nxc" else None)
    detected = tools.detect({"netexec": {"binaries": ["nxc", "netexec"], "required": False, "packages": {}}})
    assert detected["netexec"] == "/usr/bin/nxc"
