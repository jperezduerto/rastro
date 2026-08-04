# AGENTS.md

Agent-facing contract for driving rastro programmatically — exit codes,
`--dry-run`, `--json`, `rastro schema`, and token-discipline for reading
results (in particular, `raw/`) — lives in
[`docs/agents.md`](docs/agents.md). Read that before scripting against
rastro.

## Root requirement

rastro requires root to scan. Unprivileged, it re-executes itself under
`sudo`, but only with a terminal attached — without one it prints the exact
command and exits `1` instead of hanging on a password prompt. Installing
rastro never needs sudo. `--dry-run` needs no root.

## Build / test

```bash
uv run --extra dev pytest
```
