# Agent-facing contract

This document is for anything driving rastro programmatically — an agent
skill, a script, a CI job. It's a stricter, more explicit version of
[`README.md`](../README.md).

## Preconditions

- rastro **requires root to scan**. When run unprivileged it re-executes
  itself under `sudo` — but only when a terminal is attached. An agent
  usually has no TTY, so instead of hanging on a password prompt rastro
  prints the exact `sudo env ... -m rastro ...` command and exits `1`.
  Either run that command, or invoke rastro from an already-root process.
  Do not retry the unprivileged invocation; the result is identical every
  time.
- `--dry-run` needs no root at all. Use it to show your human what would run
  before asking for privilege.
- rastro does not check whether you are authorized to scan the target. Confirm
  authorization before invoking it.

## Exit codes

Exit code is the only thing you should branch on programmatically — do not
parse stderr text.

| Code | Meaning | What to do |
|---|---|---|
| 0 | Completed | Read `result.json` |
| 1 | Missing required tool, or not root | Fix the environment; do not retry blindly |
| 2 | Target unreachable | Verify the address/connectivity before retrying |
| 3 | Partial — some enumeration failed | `result.json` and `report.md` were still written; check `skipped` and each artifact's `exit_code` |

## `--dry-run`

Prints the **sweep command** rastro would run to stdout, and touches nothing
on disk — no output directory is created. Exit code is always `0` unless the
target itself can't be resolved beforehand.

It is not a full command list, and must not be presented as one. Because
dry-run does not scan, no ports are known, so the per-service enumeration
commands cannot be planned — those depend entirely on what the sweep finds.
The output says so explicitly on a trailing `#` comment line. Use dry-run to
confirm *how* rastro will approach a target, not to enumerate everything it
will eventually do.

## `--json`

In addition to writing `result.json` to the output directory, `--json`
prints the same payload to stdout. Useful when the caller wants the result
in a single pipe rather than reading a file afterward. The output
directory's path is still printed as the very first line, before the JSON.

## `rastro schema`

```bash
rastro schema
```

Prints the JSON Schema for `result.json` (`rastro.cli.RESULT_SCHEMA`).
Validate against it before parsing untrusted or version-drifted output.

## Token / context discipline

`raw/` can hold megabytes of tool output across a single run. Reading it
wholesale is the single most likely way to blow an agent's context budget
for no benefit — nothing in `raw/` is more informative than what's already
been extracted into `result.json`.

1. Read `result.json` first. `findings`, `buckets`, and `skipped` are
   almost always sufficient.
2. Open a specific file under `raw/` only when a finding's
   `source_artifact` names it, and read only that file.
3. Never enumerate or read the whole `raw/` directory.

See [`skills/rastro/SKILL.md`](../skills/rastro/SKILL.md) for the packaged
version of this guidance.
