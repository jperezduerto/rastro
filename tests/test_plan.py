from pathlib import Path

import pytest

from rastro.model import Context, Host, Port, Service
from rastro.stages.plan import TemplateError, build_plan, render_template

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


def test_tls_port_renders_https_and_plain_port_renders_http(tmp_path):
    # 443 probed over plaintext http:// is an unusable request that also drags the
    # whole run down to EXIT_PARTIAL on the nonzero curl exit.
    https = render_template(
        "curl {scheme}://{target}:{port}/", target="10.0.0.5", port=443, output_dir=tmp_path
    )
    http = render_template(
        "curl {scheme}://{target}:{port}/", target="10.0.0.5", port=80, output_dir=tmp_path
    )
    assert https.startswith("curl https://")
    assert http.startswith("curl http://")


def test_unknown_placeholder_raises_template_error(tmp_path):
    with pytest.raises(TemplateError):
        render_template("gobuster -w {wordlist}", target="t", port=80, output_dir=tmp_path)


def test_stray_brace_in_a_command_raises_template_error(tmp_path):
    # awk/curl format strings are the realistic version of this.
    with pytest.raises(TemplateError):
        render_template("awk '{print $1}'", target="t", port=80, output_dir=tmp_path)


def test_unrenderable_template_is_skipped_and_does_not_abort_the_plan(tmp_path):
    # build_plan runs mid-scan; raising here would discard the sweep and -sV results.
    rules = {
        "version": 1,
        "services": {
            "smb": {
                "ports": [445],
                "enum": [
                    {"id": "bad", "tool": "netexec", "command": "nxc {wordlist} {target}",
                     "timeout": 60, "requires_confidence": "guess"},
                    {"id": "good", "tool": "netexec", "command": "nxc smb {target} --shares",
                     "timeout": 60, "requires_confidence": "guess"},
                ],
            }
        },
    }
    host = Host(target="10.0.0.5")
    host.ports = [Port(number=445, service=Service(name="smb", confidence="guess"))]
    ctx = Context(target="10.0.0.5", output_dir=tmp_path, rules=rules,
                  tools={"netexec": "/usr/bin/nxc"})

    plan, skipped = build_plan(host, ctx)          # must not raise

    assert [p.entry_id for p in plan] == ["good"]  # the rest of the plan survives
    bad = [s for s in skipped if s["tool"] == "netexec"][0]
    assert "wordlist" in bad["reason"]                       # names the bad placeholder
    assert bad["would_have_run"] == ["nxc {wordlist} {target}"]  # and the raw template


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


def test_port_with_no_rules_is_recorded_as_skipped(tmp_path):
    # "Nothing skipped" must never be reported while open ports went untouched.
    host = Host(target="10.0.0.5")
    host.ports = [Port(number=9999, service=Service(name="whatever", confidence="confirmed"))]
    plan, skipped = build_plan(host, _ctx(tmp_path, {}))
    assert plan == []
    assert len(skipped) == 1
    assert "no enumeration rules" in skipped[0]["reason"]
    assert "9999" in skipped[0]["reason"]


def test_port_with_no_service_is_recorded_as_skipped(tmp_path):
    host = Host(target="10.0.0.5")
    host.ports = [Port(number=40376)]
    plan, skipped = build_plan(host, _ctx(tmp_path, {}))
    assert plan == []
    assert len(skipped) == 1
    assert "no service identified" in skipped[0]["reason"]
