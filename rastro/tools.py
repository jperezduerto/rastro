# rastro/tools.py
"""What is actually installed on this machine.

rastro's behaviour depends entirely on the local toolset, so this runs before any
target is touched and its result is recorded in the run output.
"""
from __future__ import annotations

import shutil
from typing import Any


def detect(tool_rules: dict[str, Any]) -> dict[str, str | None]:
    """Map each configured tool to a resolved binary path, or None if absent.

    A tool may declare several binary names (netexec ships as both `nxc` and
    `netexec`); the first one found wins.
    """
    found: dict[str, str | None] = {}
    for name, spec in tool_rules.items():
        path = None
        for binary in spec.get("binaries", []):
            path = shutil.which(binary)
            if path:
                break
        found[name] = path
    return found
