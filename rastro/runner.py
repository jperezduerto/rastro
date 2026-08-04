# rastro/runner.py
"""The only module that executes external commands.

Every invocation is bounded by a timeout and every byte of output is written to
disk rather than held in memory: an nmap sweep can emit megabytes, and the JSON
result references the file instead of embedding it.
"""
from __future__ import annotations

import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from .model import Artifact

_UNSAFE_SLUG = re.compile(r"[^a-zA-Z0-9._-]+")


@dataclass
class CommandSpec:
    command: str
    tool: str
    timeout: int
    slug: str


def _safe_slug(slug: str) -> str:
    """Slugs name files; a rules-supplied id must never escape the raw/ directory."""
    cleaned = _UNSAFE_SLUG.sub("-", slug).strip("-")
    return cleaned or "artifact"


def run_command(
    command: str, *, tool: str, timeout: int, output_dir: Path, slug: str
) -> Artifact:
    """Run one command, capture combined output to raw/<slug>.txt, never raise."""
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    relative = f"raw/{_safe_slug(slug)}.txt"
    target_file = output_dir / relative

    started = time.monotonic()
    timed_out = False
    try:
        completed = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout, stderr, exit_code = completed.stdout, completed.stderr, completed.returncode
    except subprocess.TimeoutExpired as expired:
        timed_out = True
        stdout = expired.stdout.decode(errors="replace") if isinstance(expired.stdout, bytes) else (expired.stdout or "")
        stderr = expired.stderr.decode(errors="replace") if isinstance(expired.stderr, bytes) else (expired.stderr or "")
        exit_code = 124  # conventional timeout code
    duration = time.monotonic() - started

    body = stdout
    if stderr:
        body = f"{body}\n--- stderr ---\n{stderr}"
    # 0600: recon output routinely contains scraped credentials.
    target_file.write_text(body)
    target_file.chmod(0o600)

    return Artifact(
        tool=tool,
        command=command,
        exit_code=exit_code,
        duration_s=round(duration, 3),
        timed_out=timed_out,
        stdout_path=relative,
        slug_source=slug,
    )


def run_many(
    specs: list[CommandSpec], *, max_parallel: int, output_dir: Path
) -> list[Artifact]:
    """Run specs concurrently with a bounded pool. One failure never sinks the rest."""
    if not specs:
        return []
    workers = max(1, min(max_parallel, len(specs)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(
                run_command,
                spec.command,
                tool=spec.tool,
                timeout=spec.timeout,
                output_dir=output_dir,
                slug=spec.slug,
            )
            for spec in specs
        ]
        return [future.result() for future in futures]
