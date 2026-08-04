"""Allow `python -m rastro`, which is how rastro re-invokes itself under sudo.

A sudo-free install puts the console script in ~/.local/bin, which is not on
root's PATH; the interpreter path always is reachable.
"""
from __future__ import annotations

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
