# ReconFlow architecture

## Flow

```text
scope.json + selected root
        │
        ├── strict validation (exact authorized roots, exclusions, expiry)
        ├── operator acknowledgement ── absent => stop
        └── dry run (default) ────────── no child process, no network
                │
                └── run directory + manifest
                      ├── Subfinder (passive subdomain discovery)
                      ├── scope filter (every hostname revalidated)
                      ├── httpx (low-rate HTTP liveness probe)
                      ├── Nmap (exact scope ports, TCP connect, light version detection, T2)
                      ├── Nuclei (default; low/medium misconfig/exposure/SSL only)
                      ├── Katana (opt-in; per-input FQDN, depth 2)
                      ├── FFUF (opt-in; tiny wordlist, strict request cap)
                      └── SQLMap (opt-in; exact URL allowlist, low-risk read-only probe)
                               │
                               ├── status-only Telegram alerts
                               └── local JSON manifest + per-tool output
```

## Components
| Component | Responsibility |
|---|---|
| `scope.py` | Parse and validate schema; match domain/IP targets; enforce expiry/exclusions. |
| `commands.py` | Build argument arrays for external tools; no shell strings; keep explicit safety flags. |
| `runner.py` | Execute stages, apply timeouts, save outputs, update manifest, notify. |
| `telegram.py` | Send bounded status messages via HTTPS using environment variables. |
| `cli.py` | Validate input and expose dry-run/run, tool selection, and explicit consent. |
| `report.py` | Store stage status/timing and artifact paths in a JSON run manifest. |

## Data model
- Scope: project name, authorization contact, expiry date, exact root domains/IPs, exact excluded hosts, exact Nmap TCP port list (max 100), maximum discovered hosts (1–100), SQLMap URLs, and conservative rate caps.
- Run: opaque run ID, start/end timestamps, chosen root, stage state/duration/exit code, output artifact paths; no secrets.
- Notifications: run ID, stage, status, short reason; never target response content or credentials.

## Security rules
1. Dry-run is the default and never launches a subprocess.
2. A real run requires `--i-have-authorization` and a valid scope file whose expiry is today or later.
3. Root domain must exactly match a scope entry; wildcard roots are rejected.
4. Subfinder results are rechecked against scope and exclusions before any active tool receives them.
5. Use `subprocess.run([...], shell=False)` only; never interpolate target strings into a shell.
6. SQLMap is off by default and only accepts exact URLs listed in scope; no `--dump`, `--dbs`, `--os-shell`, `--file-read`, or writes.
7. Tool output stays local; Telegram carries status only. Secrets are environment-only and redacted in logs.
8. Per-tool timeouts and request limits are mandatory; no stealth/evasion flags.

## Repository layout

```text
reconflow/
  docs/               MVP and architecture
  reconflow/           Python CLI and orchestration
  tests/               unit and fake-tool integration tests
  examples/            scope template and local demo server
  wordlists/           tiny non-sensitive FFUF demo list
  README.md
  .env.example
```
