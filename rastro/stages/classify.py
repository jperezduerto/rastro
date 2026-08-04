"""Turn raw artifacts into buckets and evidenced findings.

The classification order is deliberate and lifted from ptest-harness: WinRM and
MSRPC are checked BEFORE web, because both speak HTTP. Getting this backwards
points directory brute-forcing at a Windows management endpoint.
"""
from __future__ import annotations

import re

from ..model import Context, Finding, Host

AD_PORTS: set[int] = {88, 389, 464, 636, 3268, 3269}
WINDOWS_RPC_PORTS: set[int] = {135, 593}
WINRM_PORTS: set[int] = {5985, 5986}
WEB_PORTS: set[int] = {
    80, 443, 3000, 5000, 5601, 7000, 8000, 8001, 8008, 8080, 8081, 8082, 8083,
    8088, 8090, 8180, 8222, 8280, 8333, 8443, 8500, 8834, 8888, 8983, 9000,
    9090, 9091, 9200, 9443, 10000, 12443, 50000,
}

# (finding id, title, interest, regex over raw artifact text)
_SIGNATURES: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    (
        "smb-signing-disabled",
        "SMB signing not required",
        "high",
        re.compile(r"message_signing:\s*disabled", re.I),
    ),
    (
        "ftp-anonymous-login",
        "Anonymous FTP login permitted",
        "high",
        re.compile(r"Anonymous FTP login allowed", re.I),
    ),
    (
        "smtp-open-relay",
        "SMTP server is an open relay",
        "high",
        re.compile(r"Server is an open relay", re.I),
    ),
    (
        "ldap-anonymous-bind",
        "LDAP allows anonymous bind",
        "medium",
        re.compile(r"namingContexts:", re.I),
    ),
    (
        "mysql-empty-password",
        "MySQL root account has an empty password",
        "high",
        re.compile(r"empty password", re.I),
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
    host.buckets = {name: sorted(ports) for name, ports in buckets.items()}

    # Run-level artifacts (sweep, version probe) carry findings too — the -sV
    # output is where most signature matches actually live.
    every_artifact = list(host.artifacts) + [a for p in host.ports for a in p.artifacts]
    for artifact in every_artifact:
        if not artifact.stdout_path:
            continue
        path = ctx.output_dir / artifact.stdout_path
        if not path.exists():
            continue
        body = path.read_text(errors="replace")
        for finding_id, title, interest, pattern in _SIGNATURES:
            match = pattern.search(body)
            if not match:
                continue
            host.findings.append(
                Finding(
                    id=finding_id,
                    title=title,
                    interest=interest,
                    evidence=match.group(0)[:200],
                    source_artifact=artifact.stdout_path,
                )
            )
    return host
