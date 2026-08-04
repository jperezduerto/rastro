"""Render a Host into report.md. Pure: takes a Host, returns a string."""
from __future__ import annotations

from ..model import Host


def render(host: Host) -> str:
    lines: list[str] = [
        f"# rastro — {host.target}",
        "",
        f"- **Target:** {host.target}",
        f"- **Resolved:** {host.resolved_ip or 'n/a'}",
        f"- **Started:** {host.started_at or 'n/a'}",
        f"- **Finished:** {host.finished_at or 'n/a'}",
        "",
    ]

    if host.buckets:
        lines += ["## Surfaces", ""]
        for name, ports in sorted(host.buckets.items()):
            lines.append(f"- **{name}:** {', '.join(str(p) for p in ports)}")
        lines.append("")

    lines += ["## Open ports", "", "| Port | Service | Product | Confidence |", "|---|---|---|---|"]
    for port in sorted(host.ports, key=lambda p: p.number):
        svc = port.service
        lines.append(
            f"| {port.number} | {svc.name if svc else '-'} | "
            f"{svc.product if svc else '-'} | {svc.confidence if svc else '-'} |"
        )
    lines.append("")

    lines += ["## Findings", ""]
    if host.findings:
        for finding in host.findings:
            lines += [
                f"### {finding.title}",
                "",
                f"- **Interest:** {finding.interest}",
                f"- **Evidence:** `{finding.evidence}`",
                f"- **Source:** `{finding.source_artifact}`",
                "",
            ]
    else:
        lines += ["None.", ""]

    # Always rendered, even when empty: silent degradation is the failure mode
    # that makes a scanner untrustworthy.
    lines += ["## Not run", ""]
    if host.skipped:
        lines += ["| Tool | Reason | Would have run |", "|---|---|---|"]
        for entry in host.skipped:
            would = "; ".join(entry.get("would_have_run", [])) or "-"
            lines.append(f"| {entry.get('tool', '-')} | {entry.get('reason', '-')} | `{would}` |")
    else:
        lines.append("Nothing skipped.")
    lines.append("")
    return "\n".join(lines)
