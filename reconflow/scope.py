"""Strict scope-file parsing and target matching."""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import date
from pathlib import Path
from urllib.parse import urlsplit


class ScopeError(ValueError):
    """Raised when an assessment target is not explicitly authorized."""


def _host(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ScopeError("host must be a non-empty string")
    value = value.strip().lower().rstrip(".")
    if value.startswith("*.") or "*" in value or "/" in value or "@" in value:
        raise ScopeError(f"wildcards, paths, and credentials are not allowed in host entries: {value!r}")
    try:
        return ipaddress.ip_address(value).compressed.lower()
    except ValueError:
        pass
    if ":" in value:
        raise ScopeError(f"ports are not allowed in host entries: {value!r}")
    try:
        ascii_host = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeError(f"invalid hostname: {value!r}") from exc
    if len(ascii_host) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", ascii_host):
        raise ScopeError(f"invalid hostname: {value!r}")
    if any(not label or len(label) > 63 for label in ascii_host.split(".")):
        raise ScopeError(f"invalid hostname: {value!r}")
    return ascii_host


def _host_list(payload: dict, key: str, *, required: bool = False) -> list[str]:
    raw = payload.get(key, [])
    if not isinstance(raw, list) or (required and not raw):
        raise ScopeError(f"{key} must be a {'non-empty ' if required else ''}list")
    items = [_host(item) for item in raw]
    if len(items) != len(set(items)):
        raise ScopeError(f"{key} contains duplicate entries")
    return items


def load_scope(path: str | Path, *, today: date | None = None) -> dict:
    """Load JSON scope and fail closed on malformed, wildcard, or expired entries."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ScopeError(f"cannot read scope file: {exc}") from exc
    if not isinstance(payload, dict):
        raise ScopeError("scope must be a JSON object")
    template = payload.get("template", False)
    if not isinstance(template, bool):
        raise ScopeError("template must be a boolean")
    for key in ("project", "authorized_by"):
        if not isinstance(payload.get(key), str) or not payload[key].strip():
            raise ScopeError(f"{key} must be a non-empty string")
    try:
        expires = date.fromisoformat(payload.get("expires", ""))
    except (TypeError, ValueError) as exc:
        raise ScopeError("expires must be an ISO date (YYYY-MM-DD)") from exc
    if expires < (today or date.today()):
        raise ScopeError(f"scope expired on {expires.isoformat()}")

    roots = _host_list(payload, "root_domains")
    ips = _host_list(payload, "allowed_ips")
    if not roots and not ips:
        raise ScopeError("scope must contain at least one root domain or exact IP")
    for root in roots:
        try:
            ipaddress.ip_address(root)
        except ValueError:
            if "." not in root:
                raise ScopeError(f"root domain must be a fully qualified domain: {root!r}")
        else:
            raise ScopeError("put IP roots in allowed_ips; root_domains accepts domains only")
    excludes = _host_list(payload, "excluded_hosts")
    rate = payload.get("rate_limit", 2)
    if not isinstance(rate, int) or isinstance(rate, bool) or not 1 <= rate <= 10:
        raise ScopeError("rate_limit must be an integer from 1 to 10 requests/second")
    ports = payload.get("nmap_ports")
    if not isinstance(ports, list) or not 1 <= len(ports) <= 100:
        raise ScopeError("nmap_ports must list 1 to 100 exact TCP port numbers")
    if any(not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535 for port in ports):
        raise ScopeError("nmap_ports entries must be integers from 1 to 65535 (no ranges)")
    if len(set(ports)) != len(ports):
        raise ScopeError("nmap_ports contains duplicates")
    max_hosts = payload.get("max_hosts", 50)
    if not isinstance(max_hosts, int) or isinstance(max_hosts, bool) or not 1 <= max_hosts <= 100:
        raise ScopeError("max_hosts must be an integer from 1 to 100")

    urls = payload.get("sqlmap_urls", [])
    if not isinstance(urls, list):
        raise ScopeError("sqlmap_urls must be a list")
    normalized_urls = []
    for raw in urls:
        if not isinstance(raw, str):
            raise ScopeError("every sqlmap URL must be a string")
        parsed = urlsplit(raw)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
            raise ScopeError(f"invalid or credential-bearing SQLMap URL: {raw!r}")
        host = _host(parsed.hostname)
        if not _in_scope(host, roots, ips, excludes):
            raise ScopeError(f"SQLMap URL host is out of scope: {host}")
        if raw in normalized_urls:
            raise ScopeError("sqlmap_urls contains duplicates")
        normalized_urls.append(raw)

    return {
        "project": payload["project"].strip(),
        "authorized_by": payload["authorized_by"].strip(),
        "expires": expires.isoformat(),
        "template": template,
        "root_domains": roots,
        "allowed_ips": ips,
        "excluded_hosts": excludes,
        "sqlmap_urls": normalized_urls,
        "nmap_ports": ports,
        "max_hosts": max_hosts,
        "rate_limit": rate,
    }


def _in_scope(host: str, roots: list[str], ips: list[str], excludes: list[str]) -> bool:
    try:
        canonical = _host(host)
    except ScopeError:
        return False
    is_ip = False
    try:
        ipaddress.ip_address(canonical)
        is_ip = True
    except ValueError:
        pass
    if is_ip:
        allowed = canonical in ips
    else:
        allowed = any(canonical == root or canonical.endswith("." + root) for root in roots)
    excluded = any(canonical == item or canonical.endswith("." + item) for item in excludes)
    return allowed and not excluded


def in_scope_host(host: str, scope: dict) -> bool:
    return _in_scope(host, scope["root_domains"], scope["allowed_ips"], scope["excluded_hosts"])


def validate_root(target: str, scope: dict) -> str:
    """Require the selected root to be an exact scope entry (not a child host)."""
    host = _host(target)
    if host not in scope["root_domains"] and host not in scope["allowed_ips"]:
        raise ScopeError(f"root target {host!r} is not an exact entry in the scope file")
    if host in scope["excluded_hosts"]:
        raise ScopeError(f"root target {host!r} is excluded")
    return host


def filter_hosts(hosts, scope: dict) -> list[str]:
    """Normalize, deduplicate and retain only in-scope discovered hostnames."""
    result = set()
    for raw in hosts:
        candidate = str(raw).strip().split()[0] if str(raw).strip() else ""
        if candidate and in_scope_host(candidate, scope):
            result.add(_host(candidate))
    return sorted(result)[:scope.get("max_hosts", 100)]
