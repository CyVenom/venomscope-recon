"""Fail-closed pipeline executor with bounded subprocesses and local manifests."""
from __future__ import annotations

import json
import re
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .commands import DEFAULT_TOOLS, build_plan
from .scope import ScopeError, filter_hosts, in_scope_host, validate_root
from .telegram import notify_status
from .toolchain import preflight_tools

TIMEOUTS = {"subfinder": 120, "httpx": 120, "nmap": 300, "nuclei": 300, "katana": 180, "ffuf": 45}
SECRET_TEXT = re.compile(r"(?i)\b(api[_-]?key|token|password|secret|authorization)\s*[:=]\s*([^\s,;]+)")
BEARER = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")


def _safe_text(value: str) -> str:
    value = SECRET_TEXT.sub(r"\1=[REDACTED]", value)
    return BEARER.sub("Bearer [REDACTED]", value)


def _safe_arg(arg: str) -> str:
    if "://" not in arg:
        return arg
    try:
        p = urlsplit(arg)
        if not p.query:
            return arg
        safe_query = urlencode([(k, "[REDACTED]") for k, _ in parse_qsl(p.query, keep_blank_values=True)])
        return urlunsplit((p.scheme, p.netloc, p.path, safe_query, p.fragment))
    except ValueError:
        return "[REDACTED URL]"


def _manifest(path: Path, result: dict) -> None:
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf8")


def _host_output(scope: dict, run_dir: Path, root: str) -> Path:
    raw = run_dir / "subfinder_raw.txt"
    discovered = filter_hosts(raw.read_text(encoding="utf8", errors="replace").splitlines(), scope) if raw.exists() else []
    hosts = [root] + [host for host in discovered if host != root][: scope["max_hosts"] - 1]
    out = run_dir / "scoped_hosts.txt"
    out.write_text("".join(h + "\n" for h in sorted(hosts)), encoding="utf8")
    return out


def _alive_urls(scope: dict, run_dir: Path) -> Path:
    src, dst = run_dir / "alive.jsonl", run_dir / "alive_urls.txt"
    urls = set()
    if src.exists():
        for line in src.read_text(encoding="utf8", errors="replace").splitlines():
            try:
                item = json.loads(line)
                url = item.get("url") or item.get("input") or ""
                host = urlsplit(url).hostname
                if host and in_scope_host(host, scope) and urlsplit(url).scheme in ("http", "https"):
                    urls.add(url)
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
    dst.write_text("".join(u + "\n" for u in sorted(urls)), encoding="utf8")
    return dst


def run_pipeline(
    scope: dict,
    target: str,
    run_dir: str | Path,
    *,
    dry_run: bool = True,
    consent: bool = False,
    tools=DEFAULT_TOOLS,
    ffuf_url: str | None = None,
    enable_sqlmap: bool = False,
) -> dict:
    """Plan or execute a bounded pipeline. Dry-run never writes files or starts processes."""
    root = validate_root(target, scope)
    if not dry_run and scope.get("template", False):
        raise ScopeError("example/template scope is dry-run only; replace it with an explicitly authorized scope")
    if not dry_run and not consent:
        raise ScopeError("real scans require --i-have-authorization")
    directory = Path(run_dir)
    plan = build_plan(root, scope, directory, tools=tools, ffuf_url=ffuf_url, enable_sqlmap=enable_sqlmap)
    stages = [{"name": item["name"], "argv": [_safe_arg(str(a)) for a in item["argv"]], "status": "planned" if dry_run else "pending"} for item in plan]
    result = {
        "run_id": uuid.uuid4().hex[:12], "project": scope["project"], "target": root,
        "started_at": datetime.now(timezone.utc).isoformat(), "status": "dry-run" if dry_run else "pending",
        "stages": stages,
    }
    if dry_run:
        return result

    executables = {Path(item["argv"][0]).name for item in plan}
    availability = preflight_tools(executables, run=subprocess.run)
    if availability["missing"] or availability["wrong"]:
        result["status"] = "missing-tools" if availability["missing"] else "invalid-tools"
        result["missing_tools"] = availability["missing"]
        result["wrong_tools"] = availability["wrong"]
        for stage in stages:
            stage["status"] = "not-started"
        return result

    directory.mkdir(parents=True, exist_ok=True)
    manifest_path = directory / "manifest.json"
    host_file = directory / "scoped_hosts.txt"
    host_file.write_text(root + "\n", encoding="utf8")
    result["status"] = "running"
    _manifest(manifest_path, result)
    notify_status(f"ReconFlow {result['run_id']}: started")
    began = time.monotonic()

    for stage in stages:
        name = stage["name"]
        tool = name.split("-", 1)[0]
        if tool in ("nuclei", "katana"):
            live_file = directory / "alive_urls.txt"
            if not live_file.exists() or not live_file.read_text(encoding="utf8").strip():
                stage["status"] = "skipped-no-live-urls"
                _manifest(manifest_path, result)
                continue
        stage_start = time.monotonic()
        notify_status(f"ReconFlow {result['run_id']}: {name} started")
        argv = plan[stages.index(stage)]["argv"]
        try:
            completed = subprocess.run(
                argv, shell=False, cwd=str(directory), capture_output=True, text=True,
                timeout=TIMEOUTS.get(tool, 60), check=False,
            )
            stdout, stderr = _safe_text(completed.stdout or ""), _safe_text(completed.stderr or "")
            (directory / f"{name}.stdout.txt").write_text(stdout, encoding="utf8")
            (directory / f"{name}.stderr.txt").write_text(stderr, encoding="utf8")
            stage["exit_code"] = completed.returncode
            stage["duration_seconds"] = round(time.monotonic() - stage_start, 2)
            stage["status"] = "completed" if completed.returncode == 0 else "failed"
            if completed.returncode == 0 and tool == "subfinder":
                host_file = _host_output(scope, directory, root)
            if completed.returncode == 0 and tool == "httpx":
                _alive_urls(scope, directory)
            if completed.returncode != 0:
                stage["reason"] = "tool exited non-zero; see local stderr artifact"
        except subprocess.TimeoutExpired:
            stage["status"] = "timed-out"
            stage["duration_seconds"] = round(time.monotonic() - stage_start, 2)
            stage["reason"] = f"exceeded {TIMEOUTS.get(tool, 60)} second timeout"
        except OSError as exc:
            stage["status"] = "failed"
            stage["reason"] = _safe_text(str(exc))
        _manifest(manifest_path, result)
        notify_status(f"ReconFlow {result['run_id']}: {name} {stage['status']}")
        if stage["status"] not in ("completed", "skipped-no-live-urls"):
            result["status"] = "failed"
            break

    if result["status"] == "running":
        result["status"] = "completed"
    result["duration_seconds"] = round(time.monotonic() - began, 2)
    result["finished_at"] = datetime.now(timezone.utc).isoformat()
    _manifest(manifest_path, result)
    notify_status(f"ReconFlow {result['run_id']}: {result['status']} in {result['duration_seconds']}s")
    return result
