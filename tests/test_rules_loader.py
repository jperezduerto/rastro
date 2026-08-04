import pytest

from rastro.rules.loader import RulesError, load_services, load_tools


def test_shipped_services_load_and_include_smb():
    rules = load_services()
    assert rules["version"] == 1
    assert "smb" in rules["services"]
    assert 445 in rules["services"]["smb"]["ports"]


def test_shipped_tools_mark_nmap_required():
    tools = load_tools()
    assert tools["nmap"]["required"] is True
    assert "apt" in tools["nmap"]["packages"]


def test_every_enum_entry_declares_a_known_confidence():
    rules = load_services()
    for name, svc in rules["services"].items():
        for entry in svc.get("enum", []):
            assert entry["requires_confidence"] in {"guess", "banner", "confirmed"}, name


def test_malformed_rules_fail_loudly_at_load(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\nservices:\n  smb:\n    ports: not-a-list\n")
    with pytest.raises(RulesError, match="ports"):
        load_services(bad)


def test_unknown_confidence_is_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "version: 1\n"
        "services:\n"
        "  smb:\n"
        "    ports: [445]\n"
        "    enum:\n"
        "      - id: x\n"
        "        tool: nxc\n"
        "        command: 'nxc smb {target}'\n"
        "        timeout: 10\n"
        "        requires_confidence: totally-sure\n"
    )
    with pytest.raises(RulesError, match="requires_confidence"):
        load_services(bad)


def test_unsupported_version_is_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 99\nservices: {}\n")
    with pytest.raises(RulesError, match="version"):
        load_services(bad)
