"""Command-line entry point for rastro."""
from __future__ import annotations

import argparse
import sys

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rastro")
    parser.add_argument("--version", action="store_true", help="print version and exit")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.version:
        print(f"rastro {__version__}")
        return 0
    return 0


def entrypoint() -> None:
    sys.exit(main())
