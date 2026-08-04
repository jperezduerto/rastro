"""Decide what to run, without running anything.

Kept separate from `enumerate` so `--dry-run` can print the exact commands rastro
would fire. Anything not planned is recorded in `skipped` with the command it
would have run: a clean report that was clean only because a tool was missing is
the failure mode that makes a scanner untrustworthy.
"""
from __future__ import annotations

import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..model import CONFIDENCE_ORDER, Context, Host
from ..runner import CommandSpec


@dataclass
class PlannedCommand:
    spec: CommandSpec
    port: int
    service: str
    entry_id: str


def render_template(
    template: str, *, target: str, port: int, output_dir: Path
) -> str:
    """Fill a rules template. Every substituted value is shell-quoted — these
    commands run as root and both target and rules file are user-controlled."""
    return template.format(
        target=shlex.quote(str(target)),
        port=int(port),
        output_dir=shlex.quote(str(output_dir)),
    )


def build_plan(host: Host, ctx: Context) -> tuple[list[PlannedCommand], list[dict[str, Any]]]:
    plan: list[PlannedCommand] = []
    skipped: list[dict[str, Any]] = []
    services = (ctx.rules.get("services") or {})

    for port in host.ports:
        if port.service is None:
            continue
        spec = services.get(port.service.name)
        if not spec:
            continue
        have = CONFIDENCE_ORDER.get(port.service.confidence, 0)

        for entry in spec.get("enum", []) or []:
            command = render_template(
                entry["command"],
                target=ctx.target,
                port=port.number,
                output_dir=ctx.output_dir,
            )
            need = CONFIDENCE_ORDER.get(entry["requires_confidence"], 0)
            if have < need:
                skipped.append({
                    "tool": entry["tool"],
                    "reason": (
                        f"confidence {port.service.confidence!r} below required "
                        f"{entry['requires_confidence']!r}"
                    ),
                    "would_have_run": [command],
                })
                continue
            if not ctx.tools.get(entry["tool"]):
                skipped.append({
                    "tool": entry["tool"],
                    "reason": "not installed",
                    "would_have_run": [command],
                })
                continue
            plan.append(
                PlannedCommand(
                    spec=CommandSpec(
                        command=command,
                        tool=entry["tool"],
                        timeout=int(entry["timeout"]),
                        slug=f"{port.number}-{entry['id']}",
                    ),
                    port=port.number,
                    service=port.service.name,
                    entry_id=entry["id"],
                )
            )
    return plan, skipped
