from rastro import deps

RULES = {
    "nmap": {"binaries": ["nmap"], "required": True, "packages": {"apt": "nmap"}},
    "gobuster": {"binaries": ["gobuster"], "required": False, "packages": {"apt": "gobuster"}},
    # No package mapping at all — rustscan is not packaged by any supported manager.
    "rustscan": {"binaries": ["rustscan"], "required": False, "packages": {}},
}


def test_homebrew_is_not_a_supported_manager():
    # brew refuses to run as root and rastro has no non-root mode, so a brew entry
    # could only ever produce mappings that silently never install anything.
    assert "brew" not in dict(deps._MANAGERS).values()
    assert "brew" not in deps._INSTALL_TEMPLATES


def test_no_shipped_tool_maps_to_an_unsupported_manager():
    from rastro.rules.loader import load_tools

    supported = set(deps._INSTALL_TEMPLATES)
    for name, spec in load_tools().items():
        assert set(spec["packages"]) <= supported, name


def test_detect_manager_prefers_first_available(monkeypatch):
    monkeypatch.setattr(deps.shutil, "which", lambda b: "/usr/bin/apt-get" if b == "apt-get" else None)
    assert deps.detect_manager() == "apt"


def test_detect_manager_returns_none_when_unknown(monkeypatch):
    monkeypatch.setattr(deps.shutil, "which", lambda b: None)
    assert deps.detect_manager() is None


def test_install_command_is_noninteractive():
    cmd = deps.install_command("apt", ["nmap", "gobuster"])
    assert "-y" in cmd
    assert "nmap" in cmd and "gobuster" in cmd


def test_install_command_quotes_package_names():
    cmd = deps.install_command("apt", ["weird; rm -rf /"])
    assert "; rm -rf /" not in cmd.replace("'weird; rm -rf /'", "")


def test_plan_installs_only_covers_missing_tools_with_a_package():
    detected = {"nmap": "/usr/bin/nmap", "gobuster": None, "rustscan": None}
    packages, skipped = deps.plan_installs(detected, RULES, "apt")
    assert packages == ["gobuster"]                      # nmap present; rustscan has no package at all
    assert [s["tool"] for s in skipped] == ["rustscan"]
    assert "apt" in skipped[0]["reason"]


def test_missing_required_flags_only_required_tools():
    detected = {"nmap": None, "gobuster": None}
    assert deps.missing_required(detected, RULES) == ["nmap"]


def test_no_manager_means_everything_missing_is_skipped():
    detected = {"gobuster": None}
    packages, skipped = deps.plan_installs(detected, RULES, None)
    assert packages == []
    assert skipped[0]["tool"] == "gobuster"
