"""Live terminal reporting: what rastro is doing, as it happens.

Everything here writes to **stderr**. stdout is reserved for machine-readable
output (`--json`, `rastro schema`, the result path), so a colourful live view
can never corrupt a pipeline.

No dependencies — the colour codes are hand-rolled ANSI, disabled automatically
when the stream is not a terminal, when NO_COLOR is set, or on a dumb terminal.
"""
from __future__ import annotations

import os
import re
import sys
from typing import Any, TextIO

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
GREY = "\033[90m"

# Lines worth surfacing from a tool's output. Everything else is banner noise.
_INTERESTING = re.compile(
    r"""(?x)
    ^\s*\d{1,5}/(?:tcp|udp)\s+open      # nmap port lines
  | ^\|                                  # nmap NSE script output
  | ^\s*HTTP/\d                          # curl status line
  | ^\s*(?:Server|X-Powered-By|Location|WWW-Authenticate):   # useful headers
  | ^\s*/\S+\s+\(Status:                 # gobuster hits
  | ^\s*(?:SMB|Share|Disk|IPC)\b         # smb enumeration
  | ^\s*\[[+*]\]                         # netexec / enum4linux markers
    """,
    re.I,
)

_NOISE = re.compile(
    r"^\s*(?:Starting Nmap|Nmap done|Host is up|Not shown|Service detection|"
    r"NSE:|Initiating|Completed|Read data files|WARNING:)",
    re.I,
)


def supports_color(stream: TextIO | None = None) -> bool:
    """Colour only when a human is actually looking at a terminal."""
    stream = stream or sys.stderr
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("TERM", "") == "dumb":
        return False
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def interesting_lines(text: str, limit: int = 6) -> list[str]:
    """The lines from a tool's output a human would actually want to see.

    Prefers recognisably meaningful lines (open ports, NSE findings, HTTP
    status, gobuster hits); falls back to the first non-noise lines so an
    unrecognised tool still shows something rather than nothing.
    """
    lines = [line.rstrip() for line in (text or "").splitlines() if line.strip()]
    picked = [line for line in lines if _INTERESTING.search(line)]
    if not picked:
        picked = [line for line in lines if not _NOISE.search(line)]
    return picked[:limit]


class Reporter:
    """Prints the live view. Silent when quiet, plain when not a terminal."""

    def __init__(self, quiet: bool = False, color: bool | None = None,
                 stream: TextIO | None = None) -> None:
        self.quiet = quiet
        self.stream = stream or sys.stderr
        self.color = supports_color(self.stream) if color is None else color

    # -- internals ---------------------------------------------------------
    def _paint(self, text: str, *codes: str) -> str:
        if not self.color or not codes:
            return text
        return f"{''.join(codes)}{text}{RESET}"

    def _write(self, text: str = "") -> None:
        if self.quiet:
            return
        print(text, file=self.stream, flush=True)

    # -- events ------------------------------------------------------------
    def banner(self, target: str, output_dir: Any) -> None:
        self._write()
        self._write(self._paint(f"  rastro  {target}", BOLD, CYAN))
        self._write(self._paint(f"  output  {output_dir}", GREY))
        self._write()

    def stage(self, name: str, detail: str = "") -> None:
        label = self._paint(f"[{name}]", BOLD, BLUE)
        self._write(f"{label} {detail}" if detail else label)

    def note(self, message: str) -> None:
        self._write(self._paint(f"  {message}", GREY))

    def warn(self, message: str) -> None:
        self._write(self._paint(f"  ! {message}", YELLOW))

    def command(self, command: str) -> None:
        """Every command rastro runs is shown before its result."""
        self._write(f"  {self._paint('$', GREY)} {self._paint(command, DIM)}")

    def result(self, exit_code: int, duration_s: float, timed_out: bool,
               excerpt: list[str] | None = None) -> None:
        if timed_out:
            mark = self._paint("timeout", YELLOW)
        elif exit_code == 0:
            mark = self._paint("ok", GREEN)
        else:
            mark = self._paint(f"exit {exit_code}", RED)
        self._write(f"    {mark} {self._paint(f'({duration_s:.1f}s)', GREY)}")
        for line in excerpt or []:
            self._write(f"      {self._paint(line[:160], GREY)}")

    def ports(self, found: list[int]) -> None:
        if not found:
            self.warn("no open ports found")
            return
        listed = ", ".join(str(p) for p in found)
        self._write(f"  {self._paint(f'{len(found)} open:', BOLD)} {listed}")

    def service(self, port: int, name: str, product: str, confidence: str) -> None:
        conf = self._paint(confidence, GREEN if confidence == "confirmed" else YELLOW)
        label = self._paint(f"{port:>6}", BOLD)
        detail = f" {product}" if product else ""
        self._write(f"  {label}  {name}{detail} {self._paint('[', GREY)}{conf}{self._paint(']', GREY)}")

    def finding(self, title: str, interest: str, evidence: str) -> None:
        colour = RED if interest == "high" else (YELLOW if interest == "medium" else CYAN)
        self._write(f"  {self._paint('!', colour, BOLD)} "
                    f"{self._paint(title, colour, BOLD)} "
                    f"{self._paint(f'({interest})', GREY)}")
        if evidence:
            self._write(f"      {self._paint(evidence[:160], GREY)}")

    # -- final summary -----------------------------------------------------
    def summary(self, host: Any) -> None:
        """The end-of-run recap: what is open, what was found, what was missed."""
        self._write()
        self._write(self._paint("-" * 64, GREY))
        self._write(self._paint(f"  SUMMARY  {host.target}", BOLD, CYAN))
        self._write(self._paint("-" * 64, GREY))

        if host.ports:
            self._write()
            self._write(self._paint("  Open ports", BOLD))
            for port in sorted(host.ports, key=lambda p: p.number):
                service = port.service
                name = service.name if service else "unknown"
                product = " ".join(
                    part for part in [
                        getattr(service, "product", ""), getattr(service, "version", "")
                    ] if part
                ) if service else ""
                confidence = service.confidence if service else "-"
                self.service(port.number, name, product, confidence)
        else:
            self._write()
            self.warn("no open ports found")

        if host.buckets:
            self._write()
            self._write(self._paint("  Surfaces", BOLD))
            for bucket, numbers in sorted(host.buckets.items()):
                ports = ", ".join(str(n) for n in numbers)
                self._write(f"    {self._paint(bucket, MAGENTA)}: {ports}")

        self._write()
        if host.findings:
            self._write(self._paint(f"  Findings ({len(host.findings)})", BOLD))
            for finding in host.findings:
                self.finding(finding.title, finding.interest, finding.evidence)
        else:
            self._write(self._paint("  Findings: none", BOLD))

        failed = [
            artifact
            for artifact in list(host.artifacts) + [a for p in host.ports for a in p.artifacts]
            if artifact.exit_code != 0
        ]
        if failed or host.skipped:
            self._write()
            if failed:
                self.warn(f"{len(failed)} command(s) failed - findings may be incomplete")
            if host.skipped:
                self.warn(f"{len(host.skipped)} step(s) not run - see 'Not run' in report.md")
        self._write()


def emit(message: str, *, quiet: bool) -> None:
    """Backwards-compatible one-liner used by the stage loop."""
    if quiet:
        return
    print(message, file=sys.stderr, flush=True)
