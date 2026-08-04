"""The canonical rastro data model. Pure data — no I/O, no side effects.

`Host` is the single object every pipeline stage receives and returns, and its
dict form is exactly what lands in result.json.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

# How a service was identified, weakest to strongest. `plan.py` gates expensive
# enumeration on this so we don't fire noisy tools at a port-number guess.
# `banner` is a reserved ordering point: identify.py only ever assigns `guess` or
# `confirmed`, so a rule requiring `banner` behaves as if it required `confirmed`.
# Kept in the scale (rather than removed) so the rules schema stays stable.
CONFIDENCE_ORDER: dict[str, int] = {"guess": 0, "banner": 1, "confirmed": 2}


@dataclass
class Service:
    name: str
    product: str = ""
    version: str = ""
    confidence: str = "guess"


@dataclass
class Artifact:
    tool: str
    command: str
    exit_code: int = 0
    duration_s: float = 0.0
    timed_out: bool = False
    stdout_path: str = ""
    parsed: dict[str, Any] = field(default_factory=dict)
    slug_source: str = ""


@dataclass
class Port:
    number: int
    protocol: str = "tcp"
    state: str = "open"
    service: Service | None = None
    artifacts: list[Artifact] = field(default_factory=list)


@dataclass
class Finding:
    id: str
    title: str
    interest: str = "info"
    evidence: str = ""
    source_artifact: str = ""
    port: int = 0


@dataclass
class Host:
    target: str
    resolved_ip: str = ""
    started_at: str = ""
    finished_at: str = ""
    tools: dict[str, str | None] = field(default_factory=dict)
    installed: list[dict[str, str]] = field(default_factory=list)
    skipped: list[dict[str, Any]] = field(default_factory=list)
    ports: list[Port] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    buckets: dict[str, list[int]] = field(default_factory=dict)
    artifacts: list[Artifact] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Host:
        ports = [
            Port(
                number=p["number"],
                protocol=p.get("protocol", "tcp"),
                state=p.get("state", "open"),
                service=Service(**p["service"]) if p.get("service") else None,
                artifacts=[Artifact(**a) for a in p.get("artifacts", [])],
            )
            for p in data.get("ports", [])
        ]
        return cls(
            target=data["target"],
            resolved_ip=data.get("resolved_ip", ""),
            started_at=data.get("started_at", ""),
            finished_at=data.get("finished_at", ""),
            tools=data.get("tools", {}),
            installed=data.get("installed", []),
            skipped=data.get("skipped", []),
            ports=ports,
            findings=[Finding(**f) for f in data.get("findings", [])],
            buckets=data.get("buckets", {}),
            artifacts=[Artifact(**a) for a in data.get("artifacts", [])],
        )


@dataclass
class Context:
    """Per-run configuration handed to every stage alongside the Host."""

    target: str
    output_dir: Path
    rules: dict[str, Any] = field(default_factory=dict)
    tools: dict[str, str | None] = field(default_factory=dict)
    dry_run: bool = False
    no_install: bool = False
    # Live reporter (rastro.render.live.Reporter). Optional so every stage stays
    # testable without a terminal; None means "report nothing".
    reporter: Any = None
    max_parallel: int = 30
    command_timeout: int = 120
