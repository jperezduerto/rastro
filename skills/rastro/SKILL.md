---
name: rastro
description: Run rastro against an authorized host to get structured recon — open ports, identified services, and evidenced findings. Use when asked to scan, enumerate, or perform reconnaissance against a host you have authorization to test.
---

# rastro

Two-phase host recon: fast port sweep, then per-service enumeration. Emits
`result.json` (canonical), `report.md` (human), and `raw/` (every tool's output).

## Before running

rastro **requires root**. If you cannot run `sudo`, ask your human rather than
retrying — the euid check fails immediately and retrying will not help.

Confirm the target is authorized before scanning. rastro does not check this.

## Commands

```bash
sudo rastro 10.0.0.5                 # normal run
sudo rastro 10.0.0.5 --dry-run       # print planned commands, touch nothing
sudo rastro 10.0.0.5 --json          # also emit result JSON on stdout
rastro schema                        # JSON Schema for result.json
```

Show your human `--dry-run` output before a real scan when the target is
unfamiliar.

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
