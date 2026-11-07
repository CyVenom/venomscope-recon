# ReconFlow

**A cautious, auditable recon pipeline for systems you are explicitly authorized to test.**

ReconFlow chains Subfinder → httpx → Nmap → Nuclei, with Katana and FFUF available as opt-ins, plus SQLMap behind a separate exact-URL opt-in. It filters discovered hosts against an expiring scope file, keeps request rates low, stores outputs locally, and can send status-only Telegram notifications.

> **Authorized use only.** Run this only against systems you own or have explicit written permission to assess. The example scope is marked `template: true`, so ReconFlow refuses to execute it. A dry run sends no network traffic and starts no subprocesses.

## What makes this version safer

- **Dry-run by default.** `python -m reconflow ...` prints a plan; it does not execute tools. Real scans require both `--run` and `--i-have-authorization`.
- **No wildcard scope.** The selected target must exactly match a domain or IP in `scope.json`. Child domains are admitted only under that exact domain boundary; exclusions apply to a host and its children.
- **Filter after discovery.** Subfinder output is normalized, capped at `max_hosts` (1–100), and rechecked before it becomes input to httpx, Nmap, Nuclei, or Katana. Redirect-following is disabled for Nuclei; Katana is opt-in and restricted to each input FQDN.
- **Bounded checks.** Rate limit is 1–10 requests/second. Nmap scans only the exact TCP ports listed in scope (`nmap_ports`, 1–100 ports) using a TCP connect scan, light version probes and T2. Nuclei is limited to low/medium misconfiguration/exposure/SSL templates and excludes intrusive, fuzz, brute-force, headless and OAST tags; FFUF has a 30-second cap and a tiny bundled list.
- **SQLMap is separate and conservative.** It is off by default, requires `--enable-sqlmap`, and can only use exact URLs listed in the scope file. It uses risk 1, level 1, BEU techniques, one thread, and no dump, database enumeration, shell, or write flags.
- **No shell interpolation.** Tools are called with argument arrays (`shell=False`), with per-tool timeouts. No tool is installed or updated automatically.
- **Telegram is status-only.** Tokens stay in environment variables. Notifications contain the run ID, stage, and status—not targets, findings, or raw output.
- **Local artifacts.** Each run writes a JSON manifest and per-tool stdout/stderr under `runs/`; those folders are git-ignored. Captured logs are locally stored and should still be reviewed before sharing.

These controls reduce accidental scope creep; they are not a guarantee against every tool, DNS, or template behavior. Review the exact plan and current tool versions before a real assessment. Findings need manual verification.

## Toolchain

| Tool | Role | Default? |
|---|---|---|
| [Subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain discovery | Yes, for domain roots |
| [httpx](https://github.com/projectdiscovery/httpx) | Low-rate HTTP liveness and metadata | Yes |
| [Nmap](https://nmap.org/) | TCP connect/version-light scan of only the exact ports in scope | Yes |
| [Nuclei](https://github.com/projectdiscovery/nuclei) | Low/medium misconfiguration, exposure and SSL templates | Yes |
| [Katana](https://github.com/projectdiscovery/katana) | Same-FQDN crawl, depth 2 | No; opt in |
| [ffuf](https://github.com/ffuf/ffuf) | Tiny-list path discovery | No; opt in with an exact base URL |
| [SQLMap](https://github.com/sqlmapproject/sqlmap) | Low-risk SQLi detection on exact allowlisted URLs | No; separate opt-in |

ReconFlow has **no Python runtime dependencies**. The external tools above must be installed separately and available on `PATH`.

## Install and dry-run

Use Python 3.11 or newer. From this folder:

```
python --version
python -m unittest discover -s tests -v
python -m reconflow --target example.com
```

The last command uses `examples/scope.example.json` and prints the default pipeline. The example file has `template: true`; it cannot be used for a live run.

For a real assessment, copy that file, replace every example value with the exact written scope you were granted, set `template` to `false`, set an expiry date, list exclusions, and add exact SQLMap URLs only if you want the separate SQLMap option. Keep scope narrow. Example:

```json
{
  "template": false,
  "project": "Approved assessment name",
  "authorized_by": "Name of the permission holder",
  "expires": "2026-12-31",
  "root_domains": ["example.com"],
  "allowed_ips": [],
  "excluded_hosts": ["admin.example.com"],
  "sqlmap_urls": [],
  "nmap_ports": [80, 443, 8080],
  "max_hosts": 50,
  "rate_limit": 2
}
```

A real scan requires an explicit consent flag each time:

```
python -m reconflow --scope scope.json --target example.com --run --i-have-authorization
```

The flag is a confirmation by the operator, not proof of permission. Only use it when you have authorization covering the selected tools and checks.

## Local-only smoke test

The included sample server binds to `127.0.0.1` only and exposes a harmless static page, `/health`, and `/robots.txt`.

Terminal 1:

```
python examples/sample_server.py --port 8080
```

Terminal 2: preview Nmap's plan first:

```
python -m reconflow --scope examples/scope.local.json --target 127.0.0.1 --tools nmap
```

If Nmap is installed, you can run this against the local-only server:

```
python -m reconflow --scope examples/scope.local.json --target 127.0.0.1 --tools nmap --run --i-have-authorization
```

It scans only TCP port 8080 on the explicitly listed loopback address, using a connect scan and light version probes, and records the result under `runs/`. Stop the sample server with `Ctrl+C`. If another local service uses port 8080, the server exits rather than replacing it.

## Optional tools

- **Katana:** `--tools subfinder,httpx,nmap,nuclei,katana`. Its field scope is `fqdn` and it only receives URLs produced by the in-scope-filtered httpx stage.
- **FFUF:** add `ffuf` to `--tools` and pass `--ffuf-url https://app.example.com`. The host must match the active scope. It uses only `wordlists/paths.txt`, the configured request rate, and a 30-second maximum.
- **SQLMap:** list each exact approved URL in `sqlmap_urls`, then add `--enable-sqlmap` to the command. Example: `--run --i-have-authorization --enable-sqlmap`. Do not add URLs unless the written authorization specifically permits SQLi testing. It never dumps databases or opens shells.
- **Choose tools:** `--tools subfinder,httpx,nmap,nuclei` is the default. Tool availability is checked before any stage starts; a missing tool stops the run before launching subprocesses.

## Telegram status notifications

1. In Telegram, open the verified **@BotFather** account and send `/newbot`.
2. Follow its prompts for a display name and a unique username ending in `bot`. Save the token privately; never paste it into chat or commit it.
3. Open your new bot and send it `/start` so Telegram creates an update for your account.
4. In Kali, enter the token without saving it in shell history, then ask Telegram for the chat ID:

```
read -rsp 'Bot token: ' RECONFLOW_TELEGRAM_BOT_TOKEN; export RECONFLOW_TELEGRAM_BOT_TOKEN; printf '\n'
python3 - <<'PY'
import json, os, urllib.request
url = 'https://api.telegram.org/bot' + os.environ['RECONFLOW_TELEGRAM_BOT_TOKEN'] + '/getUpdates'
data = json.load(urllib.request.urlopen(url, timeout=10))
ids = sorted({str(u['message']['chat']['id']) for u in data.get('result', []) if 'message' in u and 'chat' in u['message']})
print('Chat IDs:', ', '.join(ids) if ids else 'none yet — send /start to your bot and retry')
PY
```

5. Set both variables in that same terminal session. The token is read silently; the chat ID is not a password:

```
read -rp 'Chat ID: ' RECONFLOW_TELEGRAM_CHAT_ID; export RECONFLOW_TELEGRAM_CHAT_ID
```

Then run ReconFlow in that terminal. If either variable is absent, notifications are disabled. Messages contain run/stage/status only. `.env.example` documents the variable names; ReconFlow does not load `.env` automatically. If you suspect the token leaked, revoke it through BotFather and create a new one.

## Clone and run from Kali Linux

Create the GitHub repo as **private** while this is unreleased. If you use GitHub CLI, authenticate in Kali once with `gh auth login`, then:

```
gh repo clone CyVenom/reconflow
cd reconflow
python3 -m unittest discover -s tests -v
cp examples/scope.example.json scope.json
nano scope.json
```

Install the external tools separately from their official sources and ensure the ProjectDiscovery `httpx` is the one on `PATH` (ReconFlow detects and rejects the unrelated Python `httpx` command-line program). Debian-packaged tools include Nmap, FFUF, and SQLMap; ProjectDiscovery tools have their own install guides linked above. ReconFlow does not run or install them for you.

Edit `scope.json`: set `template` to `false` only after you have written permission; replace the project, permission holder, domain, expiry date, exclusions, exact port list, and target cap. For a website you own, a starting list is usually ports 80 and 443, but include only ports your permission covers. Preview first:

```
python3 -m reconflow --scope scope.json --target your-domain.example
```

Then, only with authorization covering each selected check:

```
python3 -m reconflow --scope scope.json --target your-domain.example --run --i-have-authorization
```

A private repo can be cloned by your authenticated GitHub account. Never use this against a third-party site just because it is publicly reachable; hosting provider rules and written authorization still apply.

## Artifacts

Each live run writes `runs/<timestamp>-<target>/manifest.json` plus local per-stage `.stdout.txt` and `.stderr.txt` files. The manifest records the tool, status, exit code, duration, safe/redacted command, and output paths. It does not include raw tool findings or Telegram credentials. Review any log before sharing it.

## Tests and limits

```
python -m unittest discover -s tests -v
```

Tests cover exact scope matching, wildcard/expiry rejection, exclusions, IPv4/IPv6, dry-run non-execution, consent gating, SQLMap opt-in, conservative command flags, Telegram credential handling, and an end-to-end fake-tool pass that proves out-of-scope discoveries do not reach the next stage.

The automated tests use fake tools and do **not** prove the behavior of third-party scanners. No public target has been scanned. Tool flags and templates can change; check each installed tool's current help and documentation before a real run. Domain scope is not a substitute for confirming current DNS, hosting, and written permission. ReconFlow does not promise complete coverage or zero false positives.

## Layout

```
reconflow/          scope validation, command builders, runner, Telegram sender, CLI
examples/           expiring template scope, loopback-only scope and local sample server
tests/              unit and fake-tool integration tests
wordlists/          small, non-sensitive path list for local test environments
runs/               local artifacts, ignored by Git
```

## Project

This is a new, separate project from VulnForge. I found an earlier VenomSec summary in the portfolio but no local code or GitHub repository to extend, so ReconFlow starts clean.
