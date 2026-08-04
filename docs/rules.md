# Rules: `services.yaml`

rastro's enumeration behavior is data, not code. The shipped inventory lives
at `rastro/rules/services.yaml`; you can override it entirely with
`--rules <path>` (a `--rules` file must be complete — it replaces the
built-in file, it does not merge with it). Adding or changing a service
never requires touching a `.py` file.

The file is loaded and validated by `rastro/rules/loader.py`
(`load_services`). A malformed file fails immediately at startup with a
message naming the offending entry, never partway through a scan.

## Top-level shape

```yaml
version: 1
services:
  <service-name>:
    ports: [<int>, ...]
    detect:
      nse: "<comma-separated nmap NSE script names>"
    enum:
      - id: <string>
        tool: <string>
        command: "<template>"
        timeout: <int seconds>
        requires_confidence: guess | banner | confirmed
```

- **`version`** — must be `1`. Reserved for future schema changes.
- **`services.<name>`** — one entry per service rastro can recognize. `<name>`
  is your own identifier (`http`, `smb`, `mysql`, ...); it shows up in
  `result.json` as `Service.name` and in the `report.md` open-ports table.
  - **`ports`** — a list of integer port numbers. During `identify`, an open
    port whose number appears here is a candidate for this service; nmap's
    own service/version detection can raise or confirm that candidate.
  - **`detect.nse`** — a comma-separated string of nmap NSE script names run
    during the `identify` stage to fingerprint the service (e.g. grab a
    banner, confirm a protocol). This is detection, not enumeration — it
    runs regardless of confidence.
  - **`enum`** — a list of enumeration commands to run once a port is
    identified as this service. Each entry is a dict with exactly these
    keys:

| Key | Type | Meaning |
|---|---|---|
| `id` | string | Unique identifier for this enumeration step within the service. Used to name its output file under `raw/` and to key `skipped` entries. |
| `tool` | string | The tool that runs this command; must match a key in `tools.yaml`. If that tool isn't installed, the entry is skipped. |
| `command` | string | The shell command template to run (see Placeholders below). |
| `timeout` | int | Seconds before rastro kills the command and marks the artifact `timed_out`. |
| `requires_confidence` | `guess` \| `banner` \| `confirmed` | The **minimum** identification confidence the port must have reached before this command is allowed to run. |

All five keys are required on every `enum` entry; the loader rejects an
entry missing any of them.

## The confidence scale

Identification confidence increases as `identify` learns more about a port,
weakest to strongest:

```
guess < banner < confirmed
```

- **`guess`** — the port number matched a service's `ports` list; nothing
  else is known.
- **`banner`** — nmap parsed a service banner or partial version string.
- **`confirmed`** — nmap positively identified the service (and usually its
  version).

`requires_confidence` on an `enum` entry is a **minimum**, not an exact
match: a `confirmed` port satisfies an entry that requires `guess` or
`banner` too. This exists so noisy or slow tools (e.g. `gobuster`) can be
gated behind a solid identification, while cheap probes (e.g. a plain
`curl`) can fire on a bare port-number guess. A port whose confidence is
below an entry's requirement is not skipped silently — it is recorded in
`skipped` along with the exact command that would have run, so a clean
result can always be distinguished from an under-confident one.

## Placeholders

Command templates are Python `str.format()` templates with three available
placeholders:

| Placeholder | Value |
|---|---|
| `{target}` | The scan target (hostname or IP as given on the command line) |
| `{port}` | The port number this enumeration step is running against |
| `{output_dir}` | The run's output directory |

**All substituted values are shell-quoted** (`shlex.quote`) before
substitution — `{target}` and `{output_dir}` in particular can be
influenced by command-line input or an alternate rules file, and these
commands run as root. Do not add your own quoting around a placeholder; it
is applied for you.

## Worked example: adding a new service

Suppose you want rastro to enumerate Redis (port 6379): fingerprint it with
an NSE script, then run `redis-cli info` once it's confirmed. Add this block
under `services:` in `services.yaml` (or your `--rules` override):

```yaml
services:
  redis:
    ports: [6379]
    detect:
      nse: "redis-info"
    enum:
      - id: redis-info
        tool: redis-cli
        command: "redis-cli -h {target} -p {port} info"
        timeout: 30
        requires_confidence: confirmed
```

Then declare `redis-cli` in `tools.yaml` so rastro knows how to find (and
optionally install) it:

```yaml
redis-cli:
  binaries: [redis-cli]
  required: false
  packages: {apt: redis-tools, dnf: redis, pacman: redis, brew: redis}
```

That's it — no Python changes. The next scan will identify port 6379 as
`redis`, and once nmap confirms it, run `redis-cli -h <target> -p 6379 info`
and capture the output under `raw/`.

## Overriding the shipped rules

Pass `--rules /path/to/services.yaml` to use your own file instead of the
one bundled with rastro. It must satisfy the same schema described above —
it is validated identically, and a missing or malformed file causes rastro
to exit before touching the target (exit code 1).
