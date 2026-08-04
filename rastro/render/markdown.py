"""Render a Host into report.md. Pure: takes a Host, returns a string."""
from __future__ import annotations

from ..model import Host


def _cell(value: object) -> str:
    """Make a value safe to drop into a markdown table cell.

    Product and version strings are parsed straight out of the scanned host's own
    banner, so their content is attacker-controlled. An unescaped `|` splits the
    row and corrupts a document that may be pasted into a client deliverable.
    """
    text = "-" if value is None or value == "" else str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("`", "\\`").replace("\n", " ")


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

    lines += ["## Open ports", ""]
    if host.ports:
        lines += ["| Port | Service | Product | Confidence |", "|---|---|---|---|"]
        for port in sorted(host.ports, key=lambda p: p.number):
            svc = port.service
            lines.append(
                f"| {port.number} | {_cell(svc.name) if svc else '-'} | "
                f"{_cell(svc.product) if svc else '-'} | "
                f"{_cell(svc.confidence) if svc else '-'} |"
            )
    else:
        # An empty table reads as "clean host". With -Pn nmap exits 0 against a dead
        # host too, so say it outright and let the Run commands section below show
        # whether the sweep actually worked.
        lines.append("No open ports found.")
    lines.append("")

    # Without this, a failed or empty sweep is indistinguishable from a clean host:
    # zero ports, no findings, nothing skipped, exit 0, and no sign a scan ever ran.
    lines += ["## Run commands", ""]
    if host.artifacts:
        lines += ["| Tool | Command | Exit | Output |", "|---|---|---|---|"]
        for artifact in host.artifacts:
            lines.append(
                f"| {_cell(artifact.tool)} | `{_cell(artifact.command)}` | "
                f"{artifact.exit_code} | `{_cell(artifact.stdout_path)}` |"
            )
    else:
        lines.append("No run-level commands were executed.")
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
            lines.append(
                f"| {_cell(entry.get('tool', '-'))} | {_cell(entry.get('reason', '-'))} | "
                f"`{_cell(would)}` |"
            )
    else:
        lines.append("Nothing skipped.")
    lines.append("")
    return "\n".join(lines)
