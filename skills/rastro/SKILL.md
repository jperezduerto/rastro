---
name: rastro
description: Run rastro against an authorized host to get structured recon — open ports, identified services, and evidenced findings. Use when asked to scan, enumerate, or perform reconnaissance against a host you have authorization to test.
---

# rastro

Two-phase host recon: fast port sweep, then per-service enumeration. Emits
`result.json` (canonical), `report.md` (human), and `raw/` (every tool's output).

## Before running

rastro **requires root to scan**. Run unprivileged, it re-executes itself
under `sudo` — but only when a terminal is attached. You usually have no TTY,
so rastro will instead print the exact `sudo env ... -m rastro ...` command
and exit `1` rather than hang on a password prompt. Run that command, or
invoke rastro from an already-root process. Do not retry the unprivileged
form; it fails identically every time.

`--dry-run` needs no root — use it to show your human what would run first.

Confirm the target is authorized before scanning. rastro does not check this.

## Commands

```bash
sudo rastro 10.0.0.5                 # normal run (already root, or sudo works)
rastro 10.0.0.5 --dry-run            # print the sweep command; no root needed
sudo rastro 10.0.0.5 --json --quiet  # result JSON on stdout, nothing else
rastro schema                        # JSON Schema for result.json
```

Show your human `--dry-run` output before a real scan when the target is
unfamiliar. Be accurate about what it shows: only the **sweep command**.
Dry-run does not scan, so no ports are known and the per-service enumeration
commands cannot be planned — those are decided after the sweep. Do not
describe dry-run output as the complete set of commands rastro will run.

## Exit codes

| Code | Meaning | What to do |
|---|---|---|
| 0 | Completed | Read `result.json` |
| 1 | Missing required tool, or not root | Ask your human; do not retry |
| 2 | Target unreachable | Verify the address and connectivity |
| 3 | Partial — some enumeration failed | Results are still valid; check `skipped` |

## Reading results — token discipline

`raw/` can hold **megabytes** of nmap output. Reading it wholesale will exhaust
your context and tell you nothing the JSON does not.

1. Read `result.json` first. Look at **`findings`**, **`buckets`**, and **`skipped`**.
2. Open a file under `raw/` **only** when a finding's `source_artifact` names it.
3. Never read the whole `raw/` directory.

`skipped` matters as much as `findings`: it lists what rastro could not run and
why. A short findings list may mean a clean host, or it may mean a missing tool —
`skipped` is how you tell the difference. Always report it.
