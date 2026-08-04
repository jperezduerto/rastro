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

**Installing rastro never needs `sudo`.** It installs into your own user
environment and elevates itself only when you actually run a scan, so it can
never disturb your system Python or conflict with distro packages.

rastro is not on PyPI yet. The easiest route on Kali, Debian or Ubuntu is
[pipx](https://pipx.pypa.io/), which keeps rastro in its own isolated
environment:

```bash
sudo apt install -y pipx nmap
pipx install "git+https://github.com/jperezduerto/rastro"
```

Then run it with no `sudo` prefix — rastro asks for root itself:

```bash
rastro 10.0.0.5
```

<details>
<summary>Other install methods</summary>

**From a clone**, if you want the tests and docs locally:

```bash
git clone https://github.com/jperezduerto/rastro
cd rastro
pipx install .
```

**Into a plain virtualenv** — `pip install .` alone fails on Debian-family
systems (PEP 668 marks the system Python externally managed):

```bash
python3 -m venv ~/.venvs/rastro
~/.venvs/rastro/bin/pip install "git+https://github.com/jperezduerto/rastro"
~/.venvs/rastro/bin/rastro 10.0.0.5
```

**Do not** use `sudo pip install --break-system-packages`. It works, but it
installs into the system interpreter, which is exactly what PEP 668 exists to
prevent and what a distro upgrade can break.

</details>

To uninstall: `pipx uninstall rastro-sec`.

### Docker

The image ships every scanning tool preinstalled, so nothing is installed
at scan time and rastro works on hosts that are not Kali:

```bash
docker build -t rastro .
docker run --rm --net=host --cap-add=NET_RAW --cap-add=NET_ADMIN \
    -v "$PWD:/out" rastro 10.0.0.5 --no-install
```

`--net=host` and `NET_RAW`/`NET_ADMIN` are required — the sweep is a SYN
scan, which needs raw sockets, and container NAT would otherwise rewrite
the traffic and hide the real network. Results land in the directory you
mount at `/out`, owned by whoever owns that directory rather than by root.

The image has no `rustscan` (it is not in the Kali repos), so the sweep
uses the nmap fallback, which covers a fixed common-port list rather than
all 65535. Pass `--output` or bind-mount a different directory to control
where results go.

## Quickstart

```bash
rastro 10.0.0.5
```

rastro re-runs itself under `sudo` (prompting for your password), prints the
output directory as its first line, then a live view of each stage:

```
/home/you/rastro-10.0.0.5-20260804-194101
stage: discover
stage: identify
stage: enumerate
stage: classify
```

Everything lands in that directory:

```
rastro-10.0.0.5-20260804-194101/
├── report.md      # read this first
├── result.json    # the same data, structured
└── raw/           # every tool's unmodified output
```

## Using it

### Look before you scan

`--dry-run` shows the sweep command without sending a packet or writing
anything. Use it when the target is unfamiliar, or to check a rules change:

```bash
rastro 10.0.0.5 --dry-run     # no root needed: nothing runs, nothing is written
```

Per-service enumeration commands cannot be shown in advance, because which
ones apply depends on which ports turn out to be open.

### Reading the results

Open `report.md` and read it in this order:

1. **Findings** — what rastro thinks is wrong. Each one names the exact
   artifact under `raw/` that produced it, so you can verify the claim rather
   than trusting it.
2. **Not run** — what rastro *didn't* do. Read this before concluding a host
   is clean; a missing tool or an unmatched service looks identical to "no
   problems found" if you skip it.
3. **Run commands** — every command with its exit code. If a failure banner
   is present, treat the findings list as incomplete.
4. **Open ports** — the inventory, with how confident rastro is about each
   service.

Then open the specific file under `raw/` that a finding points at. That
directory can hold megabytes; there is rarely a reason to read all of it.

### "Why didn't gobuster run?"

Expensive or noisy enumeration is gated on confidence. A port whose service
was inferred only from its port number is a `guess`; one that `nmap -sV`
positively identified is `confirmed`. Rules declare a minimum:

```yaml
      - id: http-dirs
        requires_confidence: confirmed     # never fires on a bare guess
```

If a step you expected didn't happen, it will be in **Not run** with the
reason and the exact command it would have run. Nothing is dropped silently.

### Common tasks

```bash
# Keep results somewhere specific
rastro 10.0.0.5 --output /engagements/acme/host-5

# Pipe structured output straight into jq (progress goes to stderr, so
# stdout stays clean)
rastro 10.0.0.5 --json --quiet | jq '.findings[]'

# Use your own rules instead of the shipped ones
rastro 10.0.0.5 --rules ./my-services.yaml

# Don't touch the package manager; report anything missing instead
rastro 10.0.0.5 --no-install

# Machine-readable description of result.json
rastro schema
```

### Adding a service

Services and their enumeration steps are data, not code. To teach rastro a
new one, add a block to `services.yaml` — no Python required:

```yaml
  redis:
    ports: [6379]
    detect:
      nse: "redis-info"
    enum:
      - id: redis-info
        tool: nmap
        command: "nmap -Pn -p{port} --script redis-info {target}"
        timeout: 60
        requires_confidence: guess
```

See [`docs/rules.md`](docs/rules.md) for the full schema, the placeholders
available, and how `--rules` overrides work.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Password prompt on every run | Expected — rastro elevates itself to scan. Use `sudo rastro <target>` inside an already-root shell to skip it. |
| `no terminal to prompt for a sudo password` | You are in CI, cron or an agent. Run the printed `sudo env ... -m rastro ...` command, or invoke rastro from an already-root process. |
| `error: externally-managed-environment` on install | PEP 668 (Debian, Ubuntu, Kali). Install into a virtualenv, as shown above. |
| Exit code `3` and a failure banner | One or more tools exited non-zero. Check the **Run commands** table for which, then read its file under `raw/`. The results are still valid, just incomplete. |
| Findings list is empty | Check **Not run** first. An empty findings list with skipped steps means gaps in coverage, not a clean host. |
| Only common ports were scanned | `rustscan` isn't installed, so the nmap fallback ran, and it sweeps a fixed common-port list rather than all 65535. Install rustscan for a full sweep. |
| Output is owned by `root` | Only happens under a real root login (no `sudo`), where there is no invoking user to hand ownership back to. |
| A service on a non-standard port isn't enumerated | rastro names services from nmap's service column, so this usually works. If the service has no rules entry it will say so in **Not run** — add one (see above). |

## Why root

rastro **requires root to scan**, but not to install. Run it without a prefix
and it re-executes itself under `sudo`, prompting for your password:

```bash
rastro <target>
```

`sudo rastro <target>` also works if rastro is on root's PATH, but after a
user-level install it usually is not — which is precisely why rastro elevates
itself rather than leaving you to solve a PATH problem.

Elevation is guarded, not automatic. When there is **no terminal** to prompt
at — CI, cron, an agent — rastro does not hang waiting on a password. It
prints the exact command to run and exits `1`. It also refuses if `sudo` is
absent, and will not re-elevate a second time if the first attempt somehow
did not produce root.

`--dry-run` needs no root at all, since it executes nothing and writes
nothing.

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
2. **identify** — three passes. First a cheap port-number guess, so every port
   has a name even if the network is unhelpful. Then `nmap -sV`, which upgrades
   matched ports to `confirmed` and records product and version — this is also
   what recognises a service on a *non-standard* port (SSH on 10022 is named
   from nmap's own service column, not from the port number). Finally, each
   service's `detect.nse` bundle runs against its port; this is where most
   findings actually come from, since a plain `-sV` reports versions but never
   the vulnerability signal.

   Confidence is `guess` (port number only) or `confirmed` (nmap positively
   identified it). A third level, `banner`, sits between them in the ordering
   but is **reserved** — the current `identify` stage never produces it (see
   [`docs/rules.md`](docs/rules.md)).
3. **plan** — for each identified service, the YAML rules (see
   [`docs/rules.md`](docs/rules.md)) are consulted to decide which
   enumeration commands to run. A command only runs if the port's confidence
   meets the command's `requires_confidence` minimum and its tool is
   installed; everything else lands in `skipped`, along with the command
   that would have run.
4. **enumerate** — the planned commands run concurrently, each tool's raw
   output captured to a file under `raw/`.
5. **classify** — enumeration output is parsed into `findings`, each evidenced
   by the specific artifact that produced it, and ports are grouped into
   `buckets`: `web`, `ad`, `rpc`, `winrm`, or `other`. (WinRM and MSRPC both
   speak HTTP and are deliberately classified *before* `web`, so directory
   brute-forcing is never pointed at a Windows management endpoint.)

The result is written to a fresh output directory (see
[`docs/output.md`](docs/output.md) for the full layout and schema).

## Sample `report.md`

Real output, lightly trimmed, from a host running vsftpd, nginx and Samba:

```markdown
# rastro — 10.0.0.5

- **Target:** 10.0.0.5
- **Resolved:** 10.0.0.5
- **Started:** 2026-08-04T19:41:01+00:00
- **Finished:** 2026-08-04T19:43:12+00:00

## Surfaces

- **other:** 21, 445
- **web:** 80, 8888

## Open ports

| Port | Service | Product | Confidence |
|---|---|---|---|
| 21 | ftp | vsftpd | confirmed |
| 80 | http | nginx | confirmed |
| 445 | smb | Samba smbd | confirmed |
| 8082 | unknown | - | confirmed |
| 8888 | http | Werkzeug httpd | confirmed |

## Run commands

| Tool | Command | Exit | Output |
|---|---|---|---|
| rustscan | `rustscan -a 10.0.0.5 -g --ulimit 5000` | 0 | `raw/discover.txt` |
| nmap | `nmap -Pn -sV --host-timeout 300s -p21,80,445,8082,8888 10.0.0.5` | 0 | `raw/identify.txt` |
| nmap | `nmap -Pn --host-timeout 120s -p445 --script smb-os-discovery,... 10.0.0.5` | 0 | `raw/445-nse.txt` |
| curl | `curl -sSik --max-time 15 http://10.0.0.5:80/` | 0 | `raw/80-http-headers.txt` |
| gobuster | `gobuster dir -q -k -u http://10.0.0.5:80/ -w ...` | 0 | `raw/80-http-dirs.txt` |
| netexec | `nxc smb 10.0.0.5 -u '' -p '' --shares` | 1 | `raw/445-smb-shares.txt` |

**1 command(s) failed.** A short findings list may reflect those failures
rather than a clean host.

## Findings

### SMB signing not required

- **Interest:** high
- **Evidence:** `Message signing enabled but not required`
- **Source:** `raw/445-nse.txt`

## Not run

| Tool | Reason | Would have run |
|---|---|---|
| - | port 8082: no enumeration rules for service 'unknown' | `-` |
```

Three things in that report are worth pointing out, because they are the
reason it looks the way it does:

- **Run commands** lists *every* command rastro ran — the sweep, the version
  probe, the NSE bundles and each per-port enumeration step — with its exit
  code and raw-output path. That is what distinguishes a genuinely clean host
  from a scan that failed: with `-Pn`, nmap exits `0` against a dead host too.
- **The failure banner** appears whenever any command exited non-zero. Here
  `netexec` crashed, so the findings list is not trustworthy as a complete
  picture, and the report says so instead of quietly looking clean.
- **Not run** records what rastro chose not to do and why. Port 8082 was open
  and confirmed, but no service matched a rule, so nothing enumerated it.
  A short findings list can mean a clean host *or* a gap in coverage — this
  section is how you tell which.

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
