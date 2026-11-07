"""Build argv lists; all execution uses shell=False."""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlsplit

from .scope import ScopeError, in_scope_host, validate_root

DEFAULT_TOOLS = ("subfinder", "httpx", "nmap", "nuclei")
OPTIONAL_TOOLS = ("katana", "ffuf", "sqlmap")
ALL_TOOLS = DEFAULT_TOOLS + OPTIONAL_TOOLS


def build_sqlmap_command(url: str, scope: dict, output_dir: Path) -> list[str]:
    if url not in scope["sqlmap_urls"]:
        raise ScopeError("SQLMap accepts only exact URLs listed in sqlmap_urls")
    parsed = urlsplit(url)
    if not parsed.hostname or not in_scope_host(parsed.hostname, scope):
        raise ScopeError("SQLMap URL host is out of scope")
    return [
        "sqlmap", "-u", url, "--batch", "--risk=1", "--level=1",
        "--technique=BEU", "--threads=1", "--timeout=5", "--retries=0",
        "--output-dir", str(output_dir / "sqlmap"),
    ]


def _base(target: str, scope: dict, run_dir: Path) -> tuple[str, Path, Path, Path]:
    root = validate_root(target, scope)
    hosts = run_dir / "scoped_hosts.txt"
    alive = run_dir / "alive.jsonl"
    urls = run_dir / "alive_urls.txt"
    return root, hosts, alive, urls


def build_plan(
    target: str,
    scope: dict,
    run_dir: Path,
    *,
    tools=DEFAULT_TOOLS,
    ffuf_url: str | None = None,
    enable_sqlmap: bool = False,
) -> list[dict]:
    """Return ordered stages; planning is pure and does not touch the network."""
    root, hosts, alive, urls = _base(target, scope, Path(run_dir))
    selected = tuple(dict.fromkeys(tools))
    unknown = set(selected) - set(ALL_TOOLS)
    if unknown:
        raise ScopeError("unknown tool(s): " + ", ".join(sorted(unknown)))
    if "sqlmap" in selected and not enable_sqlmap:
        raise ScopeError("SQLMap requires the separate --enable-sqlmap opt-in")
    if ("nuclei" in selected or "katana" in selected) and "httpx" not in selected:
        raise ScopeError("Nuclei and Katana require httpx to produce a scope-filtered live URL list")
    if enable_sqlmap and not scope["sqlmap_urls"]:
        raise ScopeError("SQLMap opt-in needs at least one exact URL in scope.sqlmap_urls")
    if enable_sqlmap and "sqlmap" not in selected:
        selected += ("sqlmap",)
    rate = str(scope["rate_limit"])
    plan = []
    if "subfinder" in selected and root in scope["root_domains"]:
        plan.append({"name": "subfinder", "argv": ["subfinder", "-d", root, "-silent", "-o", str(Path(run_dir) / "subfinder_raw.txt")]})
    if "httpx" in selected:
        plan.append({"name": "httpx", "argv": ["httpx", "-l", str(hosts), "-silent", "-json", "-status-code", "-title", "-tech-detect", "-rate-limit", rate, "-o", str(alive)]})
    if "nmap" in selected:
        plan.append({"name": "nmap", "argv": ["nmap", "-sT", "-sV", "--version-light", "-T2", "-p", ",".join(str(p) for p in scope["nmap_ports"]), "-iL", str(hosts), "-oN", str(Path(run_dir) / "nmap.txt")]})
    if "nuclei" in selected:
        plan.append({"name": "nuclei", "argv": ["nuclei", "-l", str(urls), "-severity", "low,medium", "-tags", "misconfig,exposure,ssl", "-rl", rate, "-c", "2", "-timeout", "5", "-retries", "0", "-etags", "dos,intrusive,bruteforce,fuzz,headless,oast", "-dr", "-o", str(Path(run_dir) / "nuclei.txt")]})
    if "katana" in selected:
        plan.append({"name": "katana", "argv": ["katana", "-list", str(urls), "-fs", "fqdn", "-d", "2", "-c", "2", "-rl", rate, "-silent", "-o", str(Path(run_dir) / "katana.txt")]})
    if "ffuf" in selected:
        if not ffuf_url:
            raise ScopeError("FFUF requires --ffuf-url to be an exact in-scope URL")
        parsed = urlsplit(ffuf_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or not in_scope_host(parsed.hostname, scope):
            raise ScopeError("FFUF URL must use HTTP(S) on an in-scope host")
        if parsed.username or parsed.password:
            raise ScopeError("FFUF URL must not contain credentials")
        base_url = ffuf_url.rstrip("/") + "/FUZZ"
        plan.append({"name": "ffuf", "argv": ["ffuf", "-u", base_url, "-w", str(Path(__file__).parent.parent / "wordlists" / "paths.txt"), "-rate", rate, "-maxtime", "30", "-mc", "200,204,301,302,307,401,403", "-of", "json", "-o", str(Path(run_dir) / "ffuf.json")]})
    if enable_sqlmap:
        for i, url in enumerate(scope["sqlmap_urls"], 1):
            argv = build_sqlmap_command(url, scope, Path(run_dir))
            plan.append({"name": f"sqlmap-{i}", "argv": argv})
    if not plan:
        raise ScopeError("selected tools do not produce any applicable stages for this target")
    return plan
