# Output

## Directory layout

Each run creates a fresh output directory (mode `0700`, owned by you once
the run finishes — see "Ownership" below) and never reuses an existing one:

```
rastro-<target>-<timestamp>/
├── result.json      # canonical, machine-readable result
├── report.md        # human-readable summary
└── raw/             # every enumeration/discovery tool's raw output, one file per artifact
```

By default the directory is created under the current working directory as
`rastro-<target>-<timestamp>` (falling back to
`~/.local/share/rastro/` if the working directory isn't writable). Pass
`--output <path>` to choose the location explicitly.

**The output directory's absolute path is always printed as the first line
of stdout**, before anything else — you never have to hunt for it, including
when scripting rastro.

## Ownership

rastro runs as root, so everything it writes starts out root-owned. During
teardown (which always runs, even after a crash or Ctrl-C), rastro chowns
the entire output directory back to the invoking user using the `SUDO_UID`
/`SUDO_GID` environment variables `sudo` sets. If those aren't present (for
example, a genuine root login with no `sudo` in the chain), ownership is
left as-is — there is no non-root user to hand it back to.

## `result.json`

`rastro schema` prints this document's shape as a JSON Schema
(`rastro.cli.RESULT_SCHEMA`). The top level:

| Field | Type | Meaning |
|---|---|---|
| `target` | string | The target as given on the command line |
| `resolved_ip` | string | The resolved IP address |
| `started_at` / `finished_at` | string (ISO 8601, UTC) | Run start/end timestamps |
| `tools` | object | Tool name → resolved binary path, or `null` if not found |
| `installed` | array of object | Tools rastro installed during this run (see below) |
| `skipped` | array of object | Enumeration steps rastro did **not** run, and why (see below) |
| `ports` | array of `Port` | Every open port found |
| `artifacts` | array of `Artifact` | Top-level artifacts not tied to a specific port (e.g. the install command) |
| `findings` | array of `Finding` | Evidenced observations extracted from enumeration output |
| `buckets` | object | Bucket name → list of port numbers (e.g. `"web": [80, 443]`), used to group the report by surface |

`target`, `ports`, `findings`, `buckets`, and `skipped` are always present
(required by the schema); the rest may be empty.

### `Port`

| Field | Type | Meaning |
|---|---|---|
| `number` | int | Port number |
| `protocol` | string | `tcp` or `udp` |
| `state` | string | Port state as reported by the sweep (normally `open`) |
| `service` | `Service` or `null` | Identified service, if any |
| `artifacts` | array of `Artifact` | Enumeration output captured for this port |

### `Service`

| Field | Type | Meaning |
|---|---|---|
| `name` | string | Service identifier, matching a key in `services.yaml` |
| `product` | string | Product name nmap reported, if any |
| `version` | string | Version string nmap reported, if any |
| `confidence` | string | `guess`, `banner`, or `confirmed` — see [`docs/rules.md`](rules.md) |

### `Artifact`

One artifact per command rastro actually ran.

| Field | Type | Meaning |
|---|---|---|
| `tool` | string | Tool that produced this artifact |
| `command` | string | The exact command line that was run |
| `exit_code` | int | The command's exit code |
| `duration_s` | float | Wall-clock seconds the command took |
| `timed_out` | bool | Whether the command was killed for exceeding its `timeout` |
| `stdout_path` | string | Path to the captured output file, **relative to the output directory** (e.g. `raw/80-http-headers.txt`) |
| `parsed` | object | Any structured data extracted from this artifact's output |
| `slug_source` | string | The `enum` entry `id` (or equivalent) this artifact came from |

### `Finding`

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Finding identifier |
| `title` | string | Human-readable summary |
| `interest` | string | Severity/interest level (e.g. `info`) |
| `evidence` | string | The specific text or value that triggered this finding |
| `source_artifact` | string | The `Artifact.stdout_path` of the artifact that evidenced this finding — **every finding is traceable to the command that produced it** |
| `port` | int | The port this finding relates to, `0` if not port-specific |

### `installed` entries

Each entry records a tool rastro installed automatically during this run:
`{"tool": ..., "package": ..., "manager": ..., "at": <ISO 8601 timestamp>}`.
Only tools that actually appeared after installation are recorded — a
failed or partial install is never reported as a success.

### `skipped` entries

Each entry records something rastro chose **not** to run, and why:
`{"tool": ..., "reason": ..., "would_have_run": [<command>, ...]}`. This
happens either because the required tool wasn't installed, or because a
port's identification confidence didn't meet an `enum` entry's
`requires_confidence` minimum.

`skipped` is not a footnote — read it alongside `findings`. A short
`findings` list can mean a clean host, or it can mean rastro was missing a
tool or a port was never confidently identified. `skipped` is how you tell
those apart; `report.md`'s "Not run" section always renders it, even when
empty.

## `report.md`

A human-readable rendering of the same `Host` object: target/timing header,
a "Surfaces" section from `buckets`, an open-ports table, a "Findings"
section (or "None." if empty), and a "Not run" section listing every
`skipped` entry (or "Nothing skipped." if empty).
