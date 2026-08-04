# rastro/runner.py
"""The only module that executes external commands.

Every invocation is bounded by a timeout and every byte of output is written to
disk rather than held in memory: an nmap sweep can emit megabytes, and the JSON
result references the file instead of embedding it.
"""
from __future__ import annotations

import os
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


def _report_start(reporter, command: str) -> None:
    if reporter is not None:
        reporter.command(command)


def _report_done(reporter, artifact: Artifact, output_dir: Path) -> None:
    """Show the outcome and a short excerpt, so the operator sees findings land."""
    if reporter is None:
        return
    excerpt: list[str] = []
    if artifact.stdout_path:
        try:
            from .render.live import interesting_lines
            text = (output_dir / artifact.stdout_path).read_text(errors="replace")
            excerpt = interesting_lines(text)
        except OSError:
            excerpt = []
    reporter.result(artifact.exit_code, artifact.duration_s, artifact.timed_out, excerpt)


def run_command(
    command: str, *, tool: str, timeout: int, output_dir: Path, slug: str,
    reporter: object | None = None,
) -> Artifact:
    """Run one command, capture combined output to raw/<slug>.txt, never raise."""
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    relative = f"raw/{_safe_slug(slug)}.txt"
    target_file = output_dir / relative

    _report_start(reporter, command)
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

    try:
        raw_dir.mkdir(parents=True, exist_ok=True)
        # 0600 set at creation (not chmod'd after): recon output routinely
        # contains scraped credentials, so it must never exist world/group
        # readable, even for the instant between create and chmod.
        fd = os.open(target_file, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
    except OSError as exc:
        # Never raise: a write failure is a recorded outcome like any other.
        failed = Artifact(
            tool=tool,
            command=command,
            exit_code=exit_code if exit_code != 0 else 1,
            duration_s=round(duration, 3),
            timed_out=timed_out,
            stdout_path="",
            slug_source=slug,
            parsed={"error": f"failed to write output: {exc}"},
        )
        _report_done(reporter, failed, output_dir)
        return failed

    artifact = Artifact(
        tool=tool,
        command=command,
        exit_code=exit_code,
        duration_s=round(duration, 3),
        timed_out=timed_out,
        stdout_path=relative,
        slug_source=slug,
    )
    _report_done(reporter, artifact, output_dir)
    return artifact


def run_many(
    specs: list[CommandSpec], *, max_parallel: int, output_dir: Path,
    reporter: object | None = None,
) -> list[Artifact]:
    """Run specs concurrently with a bounded pool. One failure never sinks the rest."""
    if not specs:
        return []
    workers = max(1, min(max_parallel, len(specs)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        future_to_spec = {
            pool.submit(
                run_command,
                spec.command,
                tool=spec.tool,
                timeout=spec.timeout,
                output_dir=output_dir,
                slug=spec.slug,
                reporter=reporter,
            ): spec
            for spec in specs
        }
        results = []
        for future, spec in future_to_spec.items():
            try:
                results.append(future.result())
            except Exception as exc:  # belt-and-suspenders: run_command itself never raises
                results.append(
                    Artifact(
                        tool=spec.tool,
                        command=spec.command,
                        exit_code=1,
                        slug_source=spec.slug,
                        parsed={"error": f"unhandled failure: {exc}"},
                    )
                )
        return results
