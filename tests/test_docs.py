from pathlib import Path

from rastro.rules.loader import load_tools

ROOT = Path(__file__).parent.parent
DOCS = ["README.md", "AGENTS.md", "docs/rules.md", "docs/output.md",
        "docs/agents.md", "skills/rastro/SKILL.md"]


def test_all_documented_files_exist():
    for name in DOCS:
        assert (ROOT / name).exists(), name


def _source_files():
    # Exempt planning artifacts (which legitimately quote the forbidden strings while
    # specifying the constraint) — but NOT the shipped docs under docs/, which are
    # exactly what these tests exist to police.
    skip = {".venv", ".git", "__pycache__", "dist", "build", ".pytest_cache",
            ".superpowers", "superpowers"}
    for pattern in ("*.py", "*.yaml", "*.md", "*.toml"):
        for path in ROOT.rglob(pattern):
            if skip.isdisjoint(path.parts):
                yield path


def test_shipped_docs_are_actually_policed():
    # Guard against a skip set so broad it exempts the files these tests exist for.
    policed = {p.name for p in _source_files()}
    for required in ("rules.md", "output.md", "agents.md", "README.md", "SKILL.md"):
        assert required in policed, f"{required} is not being checked"


# Built by concatenation, not written as a literal: these tests assert that
# no *other* file contains these substrings, but writing either one out in
# full right here would make test_docs.py fail its own check the moment
# _source_files() reaches it.
_PROPRIETARY_NOTICE = "All rights" + " reserved"
_COMPANY_NAME = "Red" + "hound"


def test_no_file_contradicts_the_mit_license():
    # A proprietary header beside an MIT LICENSE is a direct contradiction.
    for path in _source_files():
        assert _PROPRIETARY_NOTICE not in path.read_text(), path


def test_no_company_attribution_anywhere():
    # rastro is independent open-source software, not a company product.
    for path in _source_files():
        assert _COMPANY_NAME not in path.read_text(), path


def test_license_is_mit_with_a_named_holder():
    text = (ROOT / "LICENSE").read_text()
    assert "MIT License" in text
    assert "Copyright (c) 2026 Jesus A. Perez Duerto" in text
    assert _COMPANY_NAME not in text


def test_readme_uses_the_pypi_package_name():
    readme = (ROOT / "README.md").read_text()
    assert "pip install rastro-sec" in readme


def test_readme_shows_sudo_because_rastro_requires_root():
    assert "sudo rastro" in (ROOT / "README.md").read_text()


def test_skill_tells_agents_to_read_result_json_before_raw():
    skill = (ROOT / "skills/rastro/SKILL.md").read_text()
    assert "result.json" in skill
    assert "raw/" in skill
    assert "source_artifact" in skill


def test_skill_documents_every_exit_code():
    skill = (ROOT / "skills/rastro/SKILL.md").read_text()
    for code in ("0", "1", "2", "3"):
        assert f"| {code} |" in skill


def test_rules_doc_lists_every_required_enum_key():
    rules_doc = (ROOT / "docs/rules.md").read_text()
    for key in ("id", "tool", "command", "timeout", "requires_confidence"):
        assert key in rules_doc


def test_every_shipped_tool_is_named_in_the_readme():
    readme = (ROOT / "README.md").read_text()
    for name in load_tools():
        assert name in readme, name


def test_readme_carries_an_authorization_notice():
    # A root-required tool that port-scans arbitrary hosts must say this up front.
    readme = (ROOT / "README.md").read_text()
    assert "## Authorization" in readme
    assert "own or" in readme and "authorization" in readme.lower()


def test_readme_states_linux_only_support():
    assert "Linux only" in (ROOT / "README.md").read_text()


def test_readme_does_not_claim_techniques_rastro_never_uses():
    # 'Why root' previously cited OS fingerprinting (-O) and UDP scanning; neither
    # appears in discovery, which is TCP-only (rustscan or -sS).
    readme = (ROOT / "README.md").read_text()
    assert "OS fingerprinting" not in readme
    assert "`-O`" not in readme


def test_readme_does_not_promise_unconditional_auto_install():
    # netexec and enum4linux-ng are apt-only, so 'installs any missing tool
    # automatically' is false on dnf and pacman.
    readme = (ROOT / "README.md").read_text()
    assert "installs any missing" not in readme
    assert "Coverage varies by distribution" in readme
    assert "skipped" in readme


# Concatenated for the same reason as the two constants above: written out in
# full, this file would fail its own check the moment _source_files() reaches it.
_BREW_MAPPING = "brew" + ":"
_BREW_INSTALL = "brew" + " install"


def test_no_doc_or_rules_file_offers_a_homebrew_package():
    # Documenting that brew is unsupported is fine; offering a mapping a reader
    # would copy is not, since it can never install anything as root.
    for path in _source_files():
        text = path.read_text()
        assert _BREW_MAPPING not in text, path
        assert _BREW_INSTALL not in text, path


def test_readme_sample_finding_matches_a_real_signature():
    # A sample finding with no corresponding signature sends readers hunting for
    # something that does not exist.
    from rastro.stages.classify import _SIGNATURES

    readme = (ROOT / "README.md").read_text()
    titles = [s.title for s in _SIGNATURES]
    assert any(f"### {title}" in readme for title in titles), titles


def test_docs_describe_dry_run_as_the_sweep_command_only():
    # --dry-run does not scan, so it cannot list per-service enumeration commands.
    for name in ("README.md", "docs/agents.md", "skills/rastro/SKILL.md"):
        text = (ROOT / name).read_text()
        assert "sweep command" in text, name


def test_docs_describe_banner_as_a_reserved_confidence_level():
    for name in ("README.md", "docs/rules.md", "docs/output.md"):
        text = (ROOT / name).read_text()
        assert "reserved" in text, name
