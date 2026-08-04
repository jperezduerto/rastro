# AGENTS.md

Agent-facing contract for driving rastro programmatically — exit codes,
`--dry-run`, `--json`, `rastro schema`, and token-discipline for reading
results (in particular, `raw/`) — lives in
[`docs/agents.md`](docs/agents.md). Read that before scripting against
rastro.

## Root requirement

rastro requires root and will not re-execute itself under `sudo`. Invoke it
as `sudo rastro <target>`; if root is unavailable, do not retry.

## Build / test

```bash
uv run --extra dev pytest
```
