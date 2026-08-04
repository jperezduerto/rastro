"""Turn open port numbers into named services, recording how confident we are.

A port-number match is a `guess`; only a version probe earns `confirmed`. The
distinction gates expensive enumeration downstream.
"""
from __future__ import annotations

import re
import shlex
from typing import Any

from ..model import Context, Host, Service
from ..runner import run_command

# Ports that are almost always HTTP even though they are not the canonical 80/443.
HTTP_HINT_PORTS: set[int] = {
    80, 280, 443, 591, 593, 832, 981, 1311, 3000, 3128, 3333, 4567, 5000, 5104,
    5800, 6543, 7000, 7474, 8000, 8001, 8008, 8014, 8042, 8069, 8080, 8081, 8088,
    8090, 8091, 8118, 8123, 8172, 8222, 8243, 8280, 8281, 8333, 8443, 8500, 8834,
    8880, 8888, 8983, 9000, 9043, 9060, 9080, 9090, 9091, 9200, 9443, 9800, 9981,
    12443, 16080, 18091, 28017, 50000,
}

def build_port_map(services: dict[str, Any]) -> dict[int, str]:
    """Invert the rules file into port -> service name. The rules are the single
    source of truth for this mapping; nothing is hardcoded."""
    mapping: dict[int, str] = {}
    for name, spec in (services.get("services") or {}).items():
        for port in spec.get("ports", []):
            mapping[int(port)] = name
    return mapping


def svc_for_port(port: int, services: dict[str, Any]) -> str:
    """Canonical service name for a port, or '' when unknown."""
    mapping = build_port_map(services)
    number = int(port)
    if number in mapping:
        return mapping[number]
    if number in HTTP_HINT_PORTS:
        return "http"
    return ""


def parse_nmap_service(text: str, port: int) -> tuple[str, str]:
    """Extract (product, version) for a port from nmap -sV output. ('', '') if absent."""
    pattern = rf"(?m)^\s*{port}/tcp\s+open\s+\S+\s+(.+)$"
    match = re.search(pattern, text or "")
    if not match:
        return ("", "")
    banner = match.group(1).strip()
    version_match = re.search(r"\b(\d+(?:\.\d+)+)\b", banner)
    version = version_match.group(1) if version_match else ""
    product = banner.replace(version, "").strip() if version else banner
    return (product, version)


def version_probe_command(target: str, ports: list[int]) -> str:
    """One -sV pass across every open port. This is what earns `confirmed`.

    The target is shell-quoted because this runs as root with user-supplied input.
    """
    port_list = ",".join(str(int(p)) for p in sorted(ports))
    return f"nmap -Pn -sV --host-timeout 300s -p{port_list} {shlex.quote(str(target))}"


def run(host: Host, ctx: Context) -> Host:
    port_map = build_port_map(ctx.rules)

    # Pass 1: cheap port-number guess, so we have a service name even if -sV fails.
    for port in host.ports:
        name = port_map.get(port.number) or ("http" if port.number in HTTP_HINT_PORTS else "")
        if not name:
            continue
        if port.service is None:
            port.service = Service(name=name, confidence="guess")
        else:
            port.service.name = port.service.name or name

    if ctx.dry_run or not host.ports:
        return host

    # Pass 2: version probe. The ONLY path to `confirmed`, which is what unlocks
    # expensive enumeration in plan.py.
    command = version_probe_command(ctx.target, [p.number for p in host.ports])
    artifact = run_command(
        command,
        tool="nmap",
        timeout=max(ctx.command_timeout, 300),
        output_dir=ctx.output_dir,
        slug="identify",
    )
    # Run-level artifact: the probe covers the whole host, not one port.
    # Recorded unconditionally so a failed probe still leaves evidence it ran.
    host.artifacts.append(artifact)
    if not artifact.stdout_path:
        return host
    path = ctx.output_dir / artifact.stdout_path
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return host

    for port in host.ports:
        product, version = parse_nmap_service(text, port.number)
        if not product and not version:
            continue
        if port.service is None:
            name = svc_for_port(port.number, ctx.rules) or "unknown"
            port.service = Service(name=name)
        port.service.product = product
        port.service.version = version
        port.service.confidence = "confirmed"
    return host
