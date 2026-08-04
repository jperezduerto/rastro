# rastro/rules/loader.py
"""Load and validate the YAML rule inventories.

A malformed user rules file must fail at startup with a precise message, never
half-way through a scan when a bad entry is finally reached.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

SUPPORTED_VERSION = 1
VALID_CONFIDENCE = {"guess", "banner", "confirmed"}
_HERE = Path(__file__).parent


class RulesError(Exception):
    """A rules file is malformed. The message names the offending entry."""


def _read_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text())
    except FileNotFoundError as exc:
        raise RulesError(f"rules file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise RulesError(f"{path}: invalid YAML: {exc}") from exc


def load_services(path: Path | None = None) -> dict[str, Any]:
    source = path or (_HERE / "services.yaml")
    data = _read_yaml(source)
    if not isinstance(data, dict):
        raise RulesError(f"{source}: top level must be a mapping")
    if data.get("version") != SUPPORTED_VERSION:
        raise RulesError(
            f"{source}: unsupported version {data.get('version')!r}, "
            f"expected {SUPPORTED_VERSION}"
        )
    services = data.get("services")
    if not isinstance(services, dict):
        raise RulesError(f"{source}: 'services' must be a mapping")

    for name, svc in services.items():
        if not isinstance(svc, dict):
            raise RulesError(f"{source}: service {name!r} must be a mapping")
        ports = svc.get("ports")
        if not isinstance(ports, list) or not all(isinstance(p, int) for p in ports):
            raise RulesError(f"{source}: service {name!r}: 'ports' must be a list of ints")
        for entry in svc.get("enum", []) or []:
            for required_key in ("id", "tool", "command", "timeout", "requires_confidence"):
                if required_key not in entry:
                    raise RulesError(
                        f"{source}: service {name!r} enum entry missing {required_key!r}"
                    )
            if entry["requires_confidence"] not in VALID_CONFIDENCE:
                raise RulesError(
                    f"{source}: service {name!r} enum {entry['id']!r}: "
                    f"requires_confidence must be one of {sorted(VALID_CONFIDENCE)}"
                )
            if not isinstance(entry["timeout"], int):
                raise RulesError(
                    f"{source}: service {name!r} enum {entry['id']!r}: timeout must be an int"
                )
    return data


def load_tools(path: Path | None = None) -> dict[str, Any]:
    source = path or (_HERE / "tools.yaml")
    data = _read_yaml(source)
    if not isinstance(data, dict):
        raise RulesError(f"{source}: top level must be a mapping")
    for name, spec in data.items():
        if not isinstance(spec, dict):
            raise RulesError(f"{source}: tool {name!r} must be a mapping")
        if not isinstance(spec.get("binaries"), list) or not spec["binaries"]:
            raise RulesError(f"{source}: tool {name!r}: 'binaries' must be a non-empty list")
        if not isinstance(spec.get("required"), bool):
            raise RulesError(f"{source}: tool {name!r}: 'required' must be a bool")
        if not isinstance(spec.get("packages"), dict):
            raise RulesError(f"{source}: tool {name!r}: 'packages' must be a mapping")
    return data
