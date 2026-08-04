"""Phase one: find open ports.

Prefers rustscan when installed (much faster), falling back to a SYN sweep. rastro
always runs as root, so -sS is unconditionally available — no unprivileged path.
"""
from __future__ import annotations

import re
import shlex

from ..model import Context, Host, Port
from ..runner import run_command

# Service ports a fast sweep can miss on a freshly booted host.
COMMON_DISCOVERY_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445,
    465, 587, 636, 993, 995, 1433, 2049, 2375, 3000, 3306, 3389, 5432,
    5601, 5900, 5985, 5986, 6379, 8000, 8008, 8080, 8081, 8088,
    8443, 8888, 9000, 9200, 10000, 11211, 27017, 50000,
)


def parse_nmap_open_ports(text: str) -> list[int]:
    """Pull 'NNN/tcp open ...' lines. Closed/filtered lines must not match."""
    found = {
        int(match.group(1))
        for match in re.finditer(r"(?m)^\s*(\d{1,5})/tcp\s+open\b", text or "")
    }
    return sorted(found)


def parse_rustscan_ports(text: str) -> list[int]:
    """Parse rustscan greppable output: 'ip -> [80,443,8080]'."""
    found: set[int] = set()
    for match in re.finditer(r"->\s*\[([0-9,\s]+)\]", text or ""):
        for token in match.group(1).split(","):
            token = token.strip()
            if token.isdigit() and 0 < int(token) <= 65535:
                found.add(int(token))
    return sorted(found)


def sweep_command(target: str, tools: dict[str, str | None]) -> tuple[str, str]:
    quoted = shlex.quote(target)
    if tools.get("rustscan"):
        return (f"rustscan -a {quoted} -g --ulimit 5000", "rustscan")
    ports = ",".join(str(p) for p in COMMON_DISCOVERY_PORTS)
    return (
        f"nmap -Pn -sS -T4 --max-retries 1 --host-timeout 180s -p{ports} {quoted}",
        "nmap",
    )


def run(host: Host, ctx: Context) -> Host:
    command, tool = sweep_command(ctx.target, ctx.tools)
    if ctx.dry_run:
        host.skipped.append(
            {"tool": tool, "reason": "dry-run", "would_have_run": [command]}
        )
        return host

    artifact = run_command(
        command,
        tool=tool,
        timeout=max(ctx.command_timeout, 300),
        output_dir=ctx.output_dir,
        slug="discover",
        reporter=ctx.reporter,
    )
    host.artifacts.append(artifact)

    ports: list[int] = []
    if artifact.stdout_path:
        stdout_file = ctx.output_dir / artifact.stdout_path
        try:
            text = stdout_file.read_text()
        except OSError:
            text = None
        if text is not None:
            ports = parse_rustscan_ports(text) if tool == "rustscan" else parse_nmap_open_ports(text)

    for number in ports:
        host.ports.append(Port(number=number))
    return host
