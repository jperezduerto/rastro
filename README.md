# rastro

rastro is a two-phase host reconnaissance CLI: a fast port sweep followed by
confidence-gated, per-service enumeration, producing a structured JSON result
alongside a human-readable report. It is the successor to my earlier
[jpscan](https://github.com/jperezduerto/jpscan) project, rebuilt around a
YAML-driven rules engine so services and enumeration steps can be added
without touching Python.

## Authorization

rastro is an active reconnaissance tool: it port-scans the target and fires
enumeration commands at whatever it finds. **Only scan systems you own or
have explicit, written authorization to test.** Unauthorized scanning is
illegal in many jurisdictions, and rastro does not and cannot verify that you
are permitted to scan a given host — that check is yours to make before you
run it.

## Supported platforms

Linux only. rastro requires root, drives Linux packaging (`apt`, `dnf`,
`pacman`) for its self-install path, and depends on `os.geteuid`, which does
not exist on Windows. It is not tested on macOS.

## Install

```bash
pip install rastro-sec
```

The installed command is `rastro`.

## Quickstart

```bash
sudo rastro 10.0.0.5
```

rastro prints the output directory as its first line, then a live view of
each stage, then exits. Open `report.md` in that directory for a human
summary, or `result.json` for the structured data.

## Why root

rastro **requires root** and refuses to run without it — it does not try to
re-execute itself under `sudo`, because self-elevation without a TTY is
unreliable. Run it as:

```bash
sudo rastro <target>
```

Root is not incidental; it is required by what rastro's default scan actually
does:

- **SYN scan (`-sS`)** — the fallback port sweep (used whenever `rustscan`
  is not installed) has nmap craft raw TCP SYN packets and never complete the
  handshake. That needs a raw socket, which only root can open.
- **Package installation** — rastro installs its own missing tools through
  the system package manager, which requires root.

Some `enum` rules also invoke nmap modes that need root (for example the DNS
and SNMP steps use `-sU`), but the two reasons above are why rastro refuses
to start without it.

Because output is written while running as root, ownership of the entire
output directory is handed back to the invoking user (via `SUDO_UID`/
`SUDO_GID`) once the scan finishes, so you are never left with root-owned
files you can't read without `sudo` again.

## How it works

rastro runs a five-stage pipeline, then renders the result:

1. **discover** — a fast port sweep (rustscan if present, nmap otherwise)
   finds open ports.
2. **identify** — nmap service/version detection maps each open port to a
   candidate service and a confidence level: `guess` (port number only) or
   `confirmed` (nmap positively identified the service). A third level,
   `banner`, sits between them in the ordering but is **reserved** — the
   current `identify` stage never produces it (see
   [`docs/rules.md`](docs/rules.md)).
3. **plan** — for each identified service, the YAML rules (see
   [`docs/rules.md`](docs/rules.md)) are consulted to decide which
   enumeration commands to run. A command only runs if the port's confidence
   meets the command's `requires_confidence` minimum and its tool is
   installed; everything else lands in `skipped`, along with the command
   that would have run.
4. **enumerate** — the planned commands run concurrently, each tool's raw
   output captured to a file under `raw/`.
5. **classify** — enumeration output is parsed into `findings`, evidenced by
   the specific artifact that produced them, and ports are grouped into
   `buckets` (e.g. `web`, `windows`) for the report.

The result is written to a fresh output directory (see
[`docs/output.md`](docs/output.md) for the full layout and schema).

## Sample `report.md`

```markdown
# rastro — 10.0.0.5

- **Target:** 10.0.0.5
- **Resolved:** 10.0.0.5
- **Started:** 2026-08-04T14:02:11+00:00
- **Finished:** 2026-08-04T14:03:47+00:00

## Surfaces

- **web:** 80, 443

## Open ports

| Port | Service | Product | Confidence |
|---|---|---|---|
| 22 | ssh | OpenSSH 9.6 | confirmed |
| 80 | http | nginx | confirmed |
| 445 | smb | Samba 4.17 | confirmed |

## Run commands

| Tool | Command | Exit | Output |
|---|---|---|---|
| nmap | `nmap -Pn -sS -T4 ... 10.0.0.5` | 0 | `raw/discover.txt` |
| nmap | `nmap -Pn -sV ... 10.0.0.5` | 0 | `raw/identify.txt` |

## Findings

### SMB signing not required

- **Interest:** high
- **Evidence:** `message signing enabled but not required`
- **Source:** `raw/445-smb-shares.txt`

## Not run

| Tool | Reason | Would have run |
|---|---|---|
| gobuster | not installed | `gobuster dir -q -k -u http://10.0.0.5:80/ ...` |
```

The **Run commands** section lists every run-level command (the sweep and the
version probe) with its exit code and raw-output path. It is what
distinguishes a genuinely clean host from a sweep that failed or found
nothing — with `-Pn`, nmap exits `0` against a dead host too.

## Flags

| Flag | Meaning |
|---|---|
| `target` | Host or IP to scan, or `schema` |
| `--output` | Explicit output directory (default: `./rastro-<target>-<timestamp>`) |
| `--rules` | Alternate `services.yaml` |
| `--dry-run` | Print the sweep command rastro would run; touches nothing on disk |
| `--no-install` | Never install missing tools |
| `--json` | Also write the result JSON to stdout |
| `--quiet` | Suppress the live view |
| `--version` | Print the rastro version |
| `rastro schema` | Print the `result.json` JSON Schema |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed |
| 1 | Missing required tool, or not root |
| 2 | Target unreachable |
| 3 | Partial — some enumeration failed |

## Tools

rastro drives external tools rather than reimplementing them. All but nmap
are optional. Unless you pass `--no-install`, rastro tries to install missing
tools through your system package manager (`apt`, `dnf`, or `pacman`).

**Coverage varies by distribution.** Not every tool is packaged for every
manager — `netexec` and `enum4linux-ng` are mapped for `apt` only, and
`rustscan` is not packaged at all. Nothing is installed silently or
partially-claimed: any tool rastro cannot install is recorded in `skipped`
with the reason, and any `enum` step that needed it is recorded there too,
alongside the exact command that would have run.

`rustscan` is optional and has **no package mapping** — install it yourself
(see [rustscan's releases](https://github.com/bee-san/RustScan/releases)) if
you want the faster sweep. Without it, rastro falls back to an nmap SYN sweep
of a common-port list, which works but is slower.

| Tool | Required | Used for |
|---|---|---|
| `nmap` | yes | Port sweep fallback, service/version detection, most NSE-based enumeration |
| `rustscan` | no | Fast initial port sweep, when installed (manual install only) |
| `curl` | no | HTTP header/response probing |
| `gobuster` | no | Directory brute-forcing (gated on `confirmed` HTTP) |
| `netexec` | no | SMB share enumeration |
| `enum4linux-ng` | no | SMB/AD user and policy enumeration |

## Documentation

- [`docs/rules.md`](docs/rules.md) — the `services.yaml` schema, and how to
  add a service without writing Python.
- [`docs/output.md`](docs/output.md) — the output directory layout and the
  full `result.json` schema.
- [`docs/agents.md`](docs/agents.md) / [`AGENTS.md`](AGENTS.md) — the
  agent-facing contract for driving rastro programmatically.

## License

MIT. See [`LICENSE`](LICENSE). rastro is independent open-source software.
