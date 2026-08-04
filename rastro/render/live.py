"""Terminal progress. Deliberately minimal — no dependency, no cursor tricks."""
from __future__ import annotations

import sys


def emit(message: str, *, quiet: bool) -> None:
    if quiet:
        return
    print(message, file=sys.stderr, flush=True)
