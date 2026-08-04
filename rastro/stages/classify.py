"""Turn raw artifacts into buckets and evidenced findings.

The classification order is deliberate and lifted from ptest-harness: WinRM and
MSRPC are checked BEFORE web, because both speak HTTP. Getting this backwards
points directory brute-forcing at a Windows management endpoint.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..model import Context, Finding, Host

AD_PORTS: set[int] = {88, 389, 464, 636, 3268, 3269}
WINDOWS_RPC_PORTS: set[int] = {135, 593}
WINRM_PORTS: set[int] = {5985, 5986}
WEB_PORTS: set[int] = {
    80, 443, 3000, 5000, 5601, 7000, 8000, 8001, 8008, 8080, 8081, 8082, 8083,
    8088, 8090, 8180, 8222, 8280, 8333, 8443, 8500, 8834, 8888, 8983, 9000,
    9090, 9091, 9200, 9443, 10000, 12443, 50000,
}


@dataclass(frozen=True)
class Signature:
    id: str
    title: str
    interest: str
    pattern: re.Pattern[str]
    services: frozenset[str]     # which service names this signature is valid for


# Scoped deliberately: an unscoped signature fires on any artifact, so an FTP
# banner containing "empty password" would be reported as a MySQL finding.
_SIGNATURES: tuple[Signature, ...] = (
    Signature(
        "smb-signing-disabled",
        "SMB signing not required",
        "high",
        # Both phrasings: smb-security-mode (legacy) and smb2-security-mode (current default).
        re.compile(r"message_signing:\s*disabled|message signing enabled but not required", re.I),
        frozenset({"smb"}),
    ),
    Signature(
        "ftp-anonymous-login",
        "Anonymous FTP login permitted",
        "high",
        re.compile(r"Anonymous FTP login allowed", re.I),
        frozenset({"ftp"}),
    ),
    Signature(
        "smtp-open-relay",
        "SMTP server is an open relay",
        "high",
        re.compile(r"Server is an open relay", re.I),
        frozenset({"smtp"}),
    ),
    Signature(
        # Renamed and downgraded: a readable RootDSE is not proof of anonymous bind.
        "ldap-rootdse-readable",
        "LDAP RootDSE is readable",
        "info",
        re.compile(r"namingContexts:", re.I),
        frozenset({"ldap"}),
    ),
    Signature(
        "mysql-empty-password",
        "MySQL account has an empty password",
        "high",
        # nmap's mysql-empty-password prints "<user> account has empty password".
        re.compile(r"\b\w+ account has empty password", re.I),
        frozenset({"mysql"}),
    ),
)


def bucket_for(port: int, service_text: str) -> str:
    """Classify a port. WinRM and RPC are tested first — both speak HTTP."""
    low = (service_text or "").lower()
    if port in WINRM_PORTS or "winrm" in low or "wsman" in low:
        return "winrm"
    if port in WINDOWS_RPC_PORTS or "msrpc" in low or "ncacn_http" in low:
        return "rpc"
    if port in AD_PORTS or any(t in low for t in ("ldap", "kerberos", "kpasswd")):
        return "ad"
    if port in WEB_PORTS or "http" in low:
        return "web"
    return "other"


def run(host: Host, ctx: Context) -> Host:
    buckets: dict[str, list[int]] = {}
    for port in host.ports:
        service = port.service
        text = " ".join(
            filter(None, [service.name, service.product, service.version])
        ) if service else ""
        buckets.setdefault(bucket_for(port.number, text), []).append(port.number)
    host.buckets = {name: sorted(ports) for name, ports in sorted(buckets.items())}

    # Which services exist on this host at all, and where.
    ports_by_service: dict[str, list[int]] = {}
    for port in host.ports:
        if port.service:
            ports_by_service.setdefault(port.service.name, []).append(port.number)

    seen: set[tuple[str, int]] = set()

    def scan(artifact, allowed: set[str], attributed_port: int | None) -> None:
        if not artifact.stdout_path:
            return
        path = ctx.output_dir / artifact.stdout_path
        try:
            body = path.read_text(errors="replace")
        except OSError:
            # exists() is True for a directory, and a root-created artifact can be
            # unreadable; neither may abort classification.
            return
        for signature in _SIGNATURES:
            if not signature.services & allowed:
                continue
            match = signature.pattern.search(body)
            if not match:
                continue
            port_number = attributed_port
            if port_number is None:
                candidates = [
                    number
                    for name in signature.services
                    for number in ports_by_service.get(name, [])
                ]
                # Only attribute when it is unambiguous.
                port_number = candidates[0] if len(candidates) == 1 else 0
            key = (signature.id, port_number)
            if key in seen:
                continue
            seen.add(key)
            host.findings.append(
                Finding(
                    id=signature.id,
                    title=signature.title,
                    interest=signature.interest,
                    evidence=match.group(0)[:200],
                    source_artifact=artifact.stdout_path,
                    port=port_number,
                )
            )

    # Per-port artifacts are scoped to that port's own service.
    for port in host.ports:
        allowed = {port.service.name} if port.service else set()
        for artifact in port.artifacts:
            scan(artifact, allowed, port.number)

    # Run-level artifacts (sweep, -sV probe) may legitimately carry evidence for any
    # service actually present on the host, but not for services that are absent.
    for artifact in host.artifacts:
        scan(artifact, set(ports_by_service), None)

    return host
