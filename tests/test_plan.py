from pathlib import Path

from rastro.model import Context, Host, Port, Service
from rastro.stages.plan import build_plan, render_template

RULES = {
    "version": 1,
    "services": {
        "smb": {
            "ports": [445],
            "enum": [
                {"id": "smb-shares", "tool": "netexec", "command": "nxc smb {target} --shares",
                 "timeout": 60, "requires_confidence": "guess"},
                {"id": "smb-users", "tool": "enum4linux-ng", "command": "enum4linux-ng -A {target}",
                 "timeout": 180, "requires_confidence": "confirmed"},
            ],
        }
    },
}


def _ctx(tmp_path, tools):
    return Context(target="10.0.0.5", output_dir=tmp_path, rules=RULES, tools=tools)


def test_template_substitutes_and_quotes(tmp_path):
    rendered = render_template(
        "nxc smb {target} -p {port}", target="10.0.0.5; id", port=445, output_dir=tmp_path
    )
    assert "'10.0.0.5; id'" in rendered
    assert rendered.endswith("-p 445")


def test_guess_confidence_runs_only_the_cheap_entry(tmp_path):
    host = Host(target="10.0.0.5")
    host.ports = [Port(number=445, service=Service(name="smb", confidence="guess"))]
    plan, skipped = build_plan(host, _ctx(tmp_path, {"netexec": "/usr/bin/nxc",
                                                     "enum4linux-ng": "/usr/bin/enum4linux-ng"}))
    assert [p.entry_id for p in plan] == ["smb-shares"]
    assert any(s["reason"].startswith("confidence") for s in skipped)


def test_confirmed_confidence_unlocks_expensive_entry(tmp_path):
    host = Host(target="10.0.0.5")
    host.ports = [Port(number=445, service=Service(name="smb", confidence="confirmed"))]
    plan, _ = build_plan(host, _ctx(tmp_path, {"netexec": "/usr/bin/nxc",
                                               "enum4linux-ng": "/usr/bin/enum4linux-ng"}))
    assert sorted(p.entry_id for p in plan) == ["smb-shares", "smb-users"]


def test_missing_tool_is_skipped_with_the_command_it_would_have_run(tmp_path):
    host = Host(target="10.0.0.5")
    host.ports = [Port(number=445, service=Service(name="smb", confidence="confirmed"))]
    plan, skipped = build_plan(host, _ctx(tmp_path, {"netexec": None,
                                                     "enum4linux-ng": "/usr/bin/enum4linux-ng"}))
    assert [p.entry_id for p in plan] == ["smb-users"]
    missing = [s for s in skipped if s["tool"] == "netexec"][0]
    assert missing["would_have_run"]                    # never silently drop work
    assert "not installed" in missing["reason"]


def test_ports_without_a_service_produce_nothing(tmp_path):
    host = Host(target="10.0.0.5")
    host.ports = [Port(number=64999)]
    plan, _ = build_plan(host, _ctx(tmp_path, {}))
    assert plan == []


def test_slug_is_unique_per_port_and_entry(tmp_path):
    host = Host(target="10.0.0.5")
    host.ports = [
        Port(number=445, service=Service(name="smb", confidence="guess")),
        Port(number=139, service=Service(name="smb", confidence="guess")),
    ]
    RULES["services"]["smb"]["ports"] = [139, 445]
    plan, _ = build_plan(host, _ctx(tmp_path, {"netexec": "/usr/bin/nxc"}))
    slugs = [p.spec.slug for p in plan]
    assert len(slugs) == len(set(slugs))
