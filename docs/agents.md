# Agent-facing contract

This document is for anything driving rastro programmatically — an agent
skill, a script, a CI job. It's a stricter, more explicit version of
[`README.md`](../README.md).

## Preconditions

- rastro **requires root**. It does not attempt to re-execute itself under
  `sudo` — invoke it as `sudo rastro <target>` yourself. If you cannot
  obtain root, do not retry; the euid check fails immediately every time and
  no amount of retrying changes that.
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

Prints every command rastro would run, one per line, to stdout, and touches
nothing on disk — no output directory is created. Use it to preview a scan
before committing to one, especially against an unfamiliar target. Exit code
is always `0` unless the target itself can't be resolved beforehand.

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
