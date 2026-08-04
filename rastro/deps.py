# rastro/deps.py
"""Self-healing dependency install.

rastro already requires root, so missing tools are installed without prompting.
Installs are restricted to distro package managers: a curl-to-shell path cannot be
version-pinned, breaks silently when upstream moves a file, and makes rastro's
behaviour unreproducible across machines.
"""
from __future__ import annotations

import shlex
import shutil
from pathlib import Path
from typing import Any

from .model import Artifact
from .runner import run_command

# probe binary -> manager key, in preference order.
# Linux distro managers only. Homebrew is deliberately absent: it refuses to run
# as root, and rastro has no non-root mode, so a brew entry could never install
# anything — it would only produce package mappings that silently never apply.
_MANAGERS: tuple[tuple[str, str], ...] = (
    ("apt-get", "apt"),
    ("dnf", "dnf"),
    ("pacman", "pacman"),
)

_INSTALL_TEMPLATES: dict[str, str] = {
    "apt": "apt-get install -y {packages}",
    "dnf": "dnf install -y {packages}",
    "pacman": "pacman -S --noconfirm {packages}",
}


def detect_manager() -> str | None:
    for binary, key in _MANAGERS:
        if shutil.which(binary):
            return key
    return None


def install_command(manager: str, packages: list[str]) -> str:
    """Build the exact non-interactive install command. Package names are quoted:
    they come from a YAML file that a user may have edited, and this runs as root."""
    quoted = " ".join(shlex.quote(p) for p in packages)
    return _INSTALL_TEMPLATES[manager].format(packages=quoted)


def missing_required(
    detected: dict[str, str | None], tool_rules: dict[str, Any]
) -> list[str]:
    return sorted(
        name
        for name, spec in tool_rules.items()
        if spec.get("required") and not detected.get(name)
    )


def plan_installs(
    detected: dict[str, str | None],
    tool_rules: dict[str, Any],
    manager: str | None,
) -> tuple[list[str], list[dict[str, Any]]]:
    """Decide what to install and what can't be. Returns (packages, skipped)."""
    packages: list[str] = []
    skipped: list[dict[str, Any]] = []
    for name, path in detected.items():
        if path:
            continue
        spec = tool_rules.get(name, {})
        package = (spec.get("packages") or {}).get(manager) if manager else None
        if package:
            packages.append(package)
        else:
            reason = (
                f"no package mapping for manager {manager!r}"
                if manager
                else "no supported package manager found"
            )
            skipped.append({"tool": name, "reason": reason, "would_have_run": []})
    return packages, skipped


def install(manager: str, packages: list[str], *, output_dir: Path) -> Artifact:
    """Run the install. Returns the artifact so the command is recorded on disk."""
    return run_command(
        install_command(manager, packages),
        tool=manager,
        timeout=600,
        output_dir=output_dir,
        slug="deps-install",
    )
