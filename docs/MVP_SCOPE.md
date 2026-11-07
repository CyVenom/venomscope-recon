# ReconFlow MVP

## One-liner
ReconFlow runs a cautious, auditable security-recon pipeline for explicitly authorized domains, with bounded tool defaults and Telegram status alerts.

## User
A security practitioner who already has written authorization and wants one reproducible command instead of manually chaining recon tools.

## One job
Given an in-scope domain and a scope file, run selected discovery and assessment tools in a controlled sequence; record exact commands, outputs, status, and timing; send short progress notifications.

## In scope for MVP
- Strict JSON scope file: exact root domains and IP addresses, exact exclusions, expiry date, and rate limits.
- Explicit acknowledgement required for real scans; dry-run by default in examples.
- Sequence: Subfinder → httpx → Nmap (only exact scope ports) → Nuclei; optional Katana, FFUF, SQLMap.
- Every discovered hostname must remain within the authorized root domain and exclusions.
- Safe command argument construction (no shell evaluation), bounded concurrency/rates/timeouts, output capture, and JSON run manifest.
- Telegram notifications using environment variables only; never include tokens or raw scan data in messages.
- Missing tools are reported clearly; a tool can be skipped only when the user selected it as optional.
- Unit tests and end-to-end orchestration tests with fake executables; no unauthorized network scans.

## Explicitly out of scope
- Exploitation, credential attacks, password spraying, stealth/evasion, persistence, destructive checks, data dumping, OS-shell access, cloud account discovery, broad internet-wide scanning, or automatic scope expansion.
- Running tools against public targets without an explicit, unexpired scope and operator acknowledgement.
- Hosted SaaS, accounts, database, billing, or a web UI.
- Installing external scanning binaries automatically.

## Success milestones
1. Scope parser refuses wildcard, excluded, expired, malformed, or out-of-scope targets.
2. Dry-run prints the complete bounded pipeline without starting network tools.
3. Fake-tool integration test proves sequencing, output hand-off, notification redaction, timeout handling, and report generation.
4. A local-only test-server run verifies the HTTP discovery path without touching external hosts.
5. Document installation and each tool's role, limitations, and authorized-use requirement.

## Safety risks and controls
- **Scope creep / subdomain takeover:** accept only exact authorized roots, filter every discovered host by DNS-label suffix, apply explicit exclusions, do not follow redirects to out-of-scope hosts.
- **Tool templates can be intrusive:** Nuclei is opt-in, severity-limited, low-rate, and excludes known intrusive tags; still review the selected templates before use.
- **SQLMap may be disruptive:** disabled by default; requires separate explicit flag and exact URL allowlist; read-only techniques only, no dump/shell options, low rate.
- **Telegram leakage:** status-only messages, token only in environment, redact secrets from captured command output and logs.
- **Resource use:** per-stage timeout, capped concurrency/rate, no unbounded retries.
- **False positives:** store raw tool output locally and say findings need manual verification.
