from pathlib import Path

from rastro.rules.loader import load_tools

ROOT = Path(__file__).parent.parent
DOCS = ["README.md", "AGENTS.md", "docs/rules.md", "docs/output.md",
        "docs/agents.md", "skills/rastro/SKILL.md"]


def test_all_documented_files_exist():
    for name in DOCS:
        assert (ROOT / name).exists(), name


def _source_files():
    # .superpowers holds planning artifacts (git-ignored) that legitimately
    # discuss the company-attribution/MIT constraint itself; it is not
    # shipped source or documentation, so it must not be policed below.
    skip = {".venv", ".git", "__pycache__", "docs", ".superpowers"}
    for pattern in ("*.py", "*.yaml", "*.md", "*.toml"):
        for path in ROOT.rglob(pattern):
            if skip.isdisjoint(path.parts):
                yield path


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
