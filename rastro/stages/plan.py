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

# Ports rastro treats as TLS when rendering `{scheme}`. Probing an HTTPS port over
# plaintext http:// yields an unusable response and a nonzero curl exit, which then
# drags an otherwise clean run down to EXIT_PARTIAL.
TLS_PORTS: frozenset[int] = frozenset({443, 8443, 9443, 12443, 5986, 8834})


@dataclass
class PlannedCommand:
    spec: CommandSpec
    port: int
    service: str
    entry_id: str


class TemplateError(Exception):
    """A rules command template could not be rendered (bad or unknown placeholder)."""


def render_template(
    template: str, *, target: str, port: int, output_dir: Path
) -> str:
    """Fill a rules template. Every substituted value is shell-quoted — these
    commands run as root and both target and rules file are user-controlled.

    A template containing any other brace (`awk '{print $1}'`, `curl -w
    '%{http_code}'`, a typo like `{wordlist}`) raises TemplateError rather than
    letting a KeyError escape: build_plan runs mid-scan, and an unhandled
    exception there would destroy results that have already been collected.
    """
    number = int(port)
    try:
        return template.format(
            target=shlex.quote(str(target)),
            port=number,
            output_dir=shlex.quote(str(output_dir)),
            scheme="https" if number in TLS_PORTS else "http",
        )
    except (KeyError, IndexError, ValueError) as exc:
        # ValueError covers a lone unbalanced brace, which fails the same way.
        detail = exc.args[0] if exc.args else exc.__class__.__name__
        raise TemplateError(f"bad placeholder {detail!r} in template: {template}") from exc


def build_plan(host: Host, ctx: Context) -> tuple[list[PlannedCommand], list[dict[str, Any]]]:
    plan: list[PlannedCommand] = []
    skipped: list[dict[str, Any]] = []
    services = (ctx.rules.get("services") or {})

    for port in host.ports:
        # An open port that gets no enumeration must say so. Reporting "nothing
        # skipped" while several ports were never touched is exactly the silent
        # degradation this project exists to avoid.
        if port.service is None:
            skipped.append({
                "tool": "-",
                "reason": f"port {port.number} open but no service identified",
                "would_have_run": [],
            })
            continue
        spec = services.get(port.service.name)
        if not spec:
            skipped.append({
                "tool": "-",
                "reason": (
                    f"port {port.number}: no enumeration rules for service "
                    f"{port.service.name!r}"
                ),
                "would_have_run": [],
            })
            continue
        have = CONFIDENCE_ORDER.get(port.service.confidence, 0)

        for entry in spec.get("enum", []) or []:
            try:
                command = render_template(
                    entry["command"],
                    target=ctx.target,
                    port=port.number,
                    output_dir=ctx.output_dir,
                )
            except TemplateError as error:
                # Never silently drop it, and never abort the scan: the sweep and
                # version probe have already run by the time we get here.
                skipped.append({
                    "tool": entry["tool"],
                    "reason": f"unrenderable command template: {error}",
                    "would_have_run": [entry["command"]],
                })
                continue
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
