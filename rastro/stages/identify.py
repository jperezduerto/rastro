"""Turn open port numbers into named services, recording how confident we are.

A port-number match is a `guess`; only a version probe earns `confirmed`. The
distinction gates expensive enumeration downstream.
"""
from __future__ import annotations

import re
import shlex
from typing import Any

from ..model import Context, Host, Service
from ..runner import CommandSpec, run_command, run_many

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


# Trailing parentheticals are nmap's extra info ("(Ubuntu Linux; protocol 2.0)")
# and routinely contain numbers that are not the service version.
_PAREN = re.compile(r"\s*\([^)]*\)")

# nmap's own service column -> the service name used in rules/services.yaml.
# Without this, anything on a non-standard port (SSH on 10022, a web app on
# 39903) is identified by -sV but never matched to a rule, so nothing enumerates
# it — the port map alone only ever recognises well-known ports.
NMAP_SERVICE_ALIASES: dict[str, str] = {
    "ssh": "ssh",
    "http": "http",
    "https": "http",
    "http-alt": "http",
    "http-proxy": "http",
    "ssl/http": "http",
    "ssl/https": "http",
    "ftp": "ftp",
    "ssl/ftp": "ftp",
    "smb": "smb",
    "microsoft-ds": "smb",
    "netbios-ssn": "smb",
    "ldap": "ldap",
    "ssl/ldap": "ldap",
    "domain": "dns",
    "smtp": "smtp",
    "ssl/smtp": "smtp",
    "submission": "smtp",
    "mysql": "mysql",
    "ms-sql-s": "mssql",
    "ms-wbt-server": "rdp",
    "snmp": "snmp",
    "nfs": "nfs",
    "wsman": "winrm",
    "mongodb": "mongodb",
}


def parse_nmap_service_name(text: str, port: int) -> str:
    """nmap's SERVICE column for a port ('ssh', 'http', ...), or '' when absent."""
    pattern = rf"(?m)^\s*{port}/tcp\s+open\s+(\S+)"
    match = re.search(pattern, text or "")
    return match.group(1).strip() if match else ""


def service_from_nmap_name(nmap_name: str, services: dict[str, Any]) -> str:
    """Map nmap's service column onto a rules service name, or '' when unmatched."""
    known = set((services.get("services") or {}))
    name = (nmap_name or "").strip().lower()
    if not name:
        return ""
    mapped = NMAP_SERVICE_ALIASES.get(name)
    if mapped and mapped in known:
        return mapped
    # An exact match against a rules service still counts, so a user who adds a
    # service keyed by nmap's own name gets it for free.
    return name if name in known else ""


def parse_nmap_service(text: str, port: int) -> tuple[str, str]:
    """Extract (product, version) for a port from nmap -sV output. ('', '') if absent.

    The version is the first whitespace-delimited token beginning with a digit;
    everything before it is the product. Splitting on token position rather than
    matching a numeric shape keeps versions like `8.2p1` and `1.3.5e` intact, and
    never deletes a digit that happens to sit inside the product name.
    """
    pattern = rf"(?m)^\s*{port}/tcp\s+open\s+\S+\s+(.+)$"
    match = re.search(pattern, text or "")
    if not match:
        return ("", "")
    banner = _PAREN.sub("", match.group(1)).strip()
    tokens = banner.split()
    for index, token in enumerate(tokens):
        if token[0].isdigit():
            return (" ".join(tokens[:index]), token)
    return (banner, "")


def nse_for_service(service_name: str, services: dict[str, Any]) -> str:
    """The NSE bundle a service declares in `detect.nse`, or '' when it declares none."""
    spec = (services.get("services") or {}).get(service_name) or {}
    return str((spec.get("detect") or {}).get("nse") or "")


def nse_probe_command(target: str, port: int, nse: str) -> str:
    """Per-port NSE probe. This is what actually produces most findings — a plain
    -sV reports versions but never the vuln/enum signal the signatures match."""
    return (
        f"nmap -Pn --host-timeout 120s -p{int(port)} "
        f"--script {shlex.quote(nse)} {shlex.quote(str(target))}"
    )


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
        # The service column is useful even when the version banner is blank: a
        # bare "10022/tcp open ssh" still tells us which rules apply.
        from_nmap = service_from_nmap_name(
            parse_nmap_service_name(text, port.number), ctx.rules
        )
        if not product and not version and not from_nmap:
            continue
        if port.service is None:
            name = svc_for_port(port.number, ctx.rules) or from_nmap or "unknown"
            port.service = Service(name=name)
        elif port.service.name in ("", "unknown") and from_nmap:
            # The port map did not recognise this port; -sV did.
            port.service.name = from_nmap
        port.service.product = product
        port.service.version = version
        port.service.confidence = "confirmed"

    # Pass 3: the NSE bundle each service declares in `detect.nse`. Run after the
    # version probe so the bundle is chosen from the *resolved* service name — a
    # service on a non-standard port gets the right scripts, which choosing from
    # the port map alone could never do.
    specs: list[CommandSpec] = []
    ports_by_slug: dict[str, Any] = {}
    for port in host.ports:
        if port.service is None:
            continue
        nse = nse_for_service(port.service.name, ctx.rules)
        if not nse:
            continue
        slug = f"{port.number}-nse"
        ports_by_slug[slug] = port
        specs.append(CommandSpec(
            command=nse_probe_command(ctx.target, port.number, nse),
            tool="nmap",
            timeout=max(ctx.command_timeout, 120),
            slug=slug,
        ))

    if specs:
        for artifact in run_many(
            specs, max_parallel=ctx.max_parallel, output_dir=ctx.output_dir
        ):
            port = ports_by_slug.get(artifact.slug_source)
            if port is not None:
                port.artifacts.append(artifact)
    return host
