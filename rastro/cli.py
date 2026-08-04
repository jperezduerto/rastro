"""Command-line entry point: the only module that enforces root and owns exit codes."""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, deps, tools
from .model import Context, Host
from .output import create_output_dir, drop_ownership, resolve_output_dir
from .render import live
from .render import markdown
from .rules.loader import RulesError, load_services, load_tools
from .stages import classify, discover, enumerate as enumerate_stage, identify

EXIT_OK = 0
EXIT_MISSING_TOOL = 1
EXIT_UNREACHABLE = 2
EXIT_PARTIAL = 3

RESULT_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "rastro result",
    "type": "object",
    "required": ["target", "ports", "findings", "buckets", "skipped"],
    "properties": {
        "target": {"type": "string"},
        "resolved_ip": {"type": "string"},
        "started_at": {"type": "string"},
        "finished_at": {"type": "string"},
        "tools": {"type": "object"},
        "installed": {"type": "array", "items": {"type": "object"}},
        "skipped": {"type": "array", "items": {"type": "object"}},
        "buckets": {"type": "object"},
        "ports": {"type": "array", "items": {"type": "object"}},
        "artifacts": {"type": "array", "items": {"type": "object"}},
        "findings": {"type": "array", "items": {"type": "object"}},
    },
}


class UnreachableTarget(Exception):
    """The target could not be resolved."""


def _is_root() -> bool:
    """True only when the effective uid is 0.

    Windows has no `os.geteuid`; rastro targets Linux, so its absence means we
    cannot verify privilege and must treat that as "not root". Failing closed is
    the only safe default for a gate that guards raw sockets, package installs,
    and chown.
    """
    geteuid = getattr(os, "geteuid", None)
    return geteuid is not None and geteuid() == 0


def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except OSError as exc:
        raise UnreachableTarget(target) from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rastro",
        description="Two-phase host reconnaissance: sweep, then per-service enumeration.",
    )
    parser.add_argument("target", nargs="?", help="host or IP to scan, or 'schema'")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--output", help="output directory")
    parser.add_argument("--rules", help="alternate services.yaml")
    parser.add_argument("--dry-run", action="store_true", help="print the plan, touch nothing")
    parser.add_argument("--no-install", action="store_true", help="never install missing tools")
    parser.add_argument("--json", action="store_true", help="also write result JSON to stdout")
    parser.add_argument("--quiet", action="store_true", help="suppress the live view")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.version:
        print(f"rastro {__version__}")
        return EXIT_OK
    if args.target == "schema":
        print(json.dumps(RESULT_SCHEMA, indent=2))
        return EXIT_OK
    if not args.target:
        build_parser().print_help()
        return EXIT_OK

    # Root is required: -sS, OS fingerprinting, UDP and raw sockets all need it.
    # Refuse rather than re-exec under sudo — self-elevation breaks without a TTY.
    if not _is_root():
        print(f"rastro must run as root. Run: sudo rastro {args.target}", file=sys.stderr)
        return EXIT_MISSING_TOOL

    try:
        service_rules = load_services(Path(args.rules) if args.rules else None)
        tool_rules = load_tools()
    except RulesError as exc:
        print(f"rules error: {exc}", file=sys.stderr)
        return EXIT_MISSING_TOOL

    try:
        resolved = resolve_target(args.target)
    except UnreachableTarget:
        print(f"cannot resolve target: {args.target}", file=sys.stderr)
        return EXIT_UNREACHABLE

    detected = tools.detect(tool_rules)
    host = Host(
        target=args.target,
        resolved_ip=resolved,
        started_at=datetime.now(timezone.utc).isoformat(),
        tools=detected,
    )

    if args.dry_run:
        # No output directory is created: --dry-run must leave the filesystem alone.
        ctx = Context(
            target=args.target, output_dir=Path.cwd(), rules=service_rules,
            tools=detected, dry_run=True,
        )
        host = discover.run(host, ctx)
        host = identify.run(host, ctx)
        host = enumerate_stage.run(host, ctx)
        for entry in host.skipped:
            for command in entry.get("would_have_run", []):
                print(command)
        return EXIT_OK

    now = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    try:
        output_dir = create_output_dir(resolve_output_dir(args.target, args.output, now))
    except FileExistsError:
        print(
            f"output directory already exists; refusing to reuse it: "
            f"{resolve_output_dir(args.target, args.output, now)}",
            file=sys.stderr,
        )
        return EXIT_MISSING_TOOL
    except OSError as error:
        print(f"cannot create output directory: {error}", file=sys.stderr)
        return EXIT_MISSING_TOOL
    print(output_dir)  # first line, always: never make the user hunt for results

    try:
        if not args.no_install:
            manager = deps.detect_manager()
            packages, skipped = deps.plan_installs(detected, tool_rules, manager)
            host.skipped.extend(skipped)
            if packages and manager:
                live.emit(f"installing: {' '.join(packages)}", quiet=args.quiet)
                # Record the install command itself: when a scan behaves differently
                # than it did last week, this is what answers "what changed".
                host.artifacts.append(deps.install(manager, packages, output_dir=output_dir))
                before = detected
                detected = tools.detect(tool_rules)
                host.tools = detected
                installed_at = datetime.now(timezone.utc).isoformat()
                for name, path in detected.items():
                    # Only claim what actually appeared — deps.install never raises,
                    # so a failed or partial install must not be reported as success.
                    if not path or before.get(name):
                        continue
                    package = (tool_rules.get(name, {}).get("packages") or {}).get(manager, name)
                    host.installed.append({
                        "tool": name, "package": package,
                        "manager": manager, "at": installed_at,
                    })

        still_missing = deps.missing_required(detected, tool_rules)
        if still_missing:
            print(f"missing required tool(s): {', '.join(still_missing)}", file=sys.stderr)
            return EXIT_MISSING_TOOL

        ctx = Context(
            target=args.target, output_dir=output_dir, rules=service_rules, tools=detected,
            no_install=args.no_install,
        )
        interrupted = False
        try:
            for stage in (discover, identify, enumerate_stage, classify):
                live.emit(f"stage: {stage.__name__.rsplit('.', 1)[-1]}", quiet=args.quiet)
                host = stage.run(host, ctx)
        except KeyboardInterrupt:
            live.emit("interrupted - writing partial results", quiet=args.quiet)
            interrupted = True

        host.finished_at = datetime.now(timezone.utc).isoformat()
        payload = json.dumps(host.to_dict(), indent=2)
        (output_dir / "result.json").write_text(payload)
        (output_dir / "result.json").chmod(0o600)
        (output_dir / "report.md").write_text(markdown.render(host))
        (output_dir / "report.md").chmod(0o600)
        if args.json:
            print(payload)

        failed = [a for a in list(host.artifacts) + [x for p in host.ports for x in p.artifacts]
                  if a.exit_code != 0]
        return EXIT_PARTIAL if (interrupted or failed) else EXIT_OK
    finally:
        # Teardown always runs: a crashed or Ctrl-C'd scan still leaves artifacts,
        # and that is exactly when the user most wants to read them.
        drop_ownership(output_dir)


def entrypoint() -> None:
    sys.exit(main())
