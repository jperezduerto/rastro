"""Phase two: run the plan.

Depth-1 by design — results here never schedule further enumeration. That keeps
runtime bounded and makes every command traceable to the sweep that justified it.
"""
from __future__ import annotations

from ..model import Context, Host
from ..runner import run_many
from .plan import build_plan


def run(host: Host, ctx: Context) -> Host:
    plan, skipped = build_plan(host, ctx)
    host.skipped.extend(skipped)

    if ctx.dry_run:
        for planned in plan:
            host.skipped.append({
                "tool": planned.spec.tool,
                "reason": "dry-run",
                "would_have_run": [planned.spec.command],
            })
        return host

    artifacts = run_many(
        [planned.spec for planned in plan],
        max_parallel=ctx.max_parallel,
        output_dir=ctx.output_dir,
    )

    by_slug = {planned.spec.slug: planned.port for planned in plan}
    ports_by_number = {port.number: port for port in host.ports}
    for artifact in artifacts:
        port_number = by_slug.get(artifact.slug_source)
        port = ports_by_number.get(port_number) if port_number else None
        if port is not None:
            port.artifacts.append(artifact)
    return host
