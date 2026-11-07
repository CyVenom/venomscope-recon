"""ReconFlow command-line entry point."""
from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

from .commands import DEFAULT_TOOLS
from .runner import run_pipeline
from .scope import ScopeError, load_scope

ROOT = Path(__file__).resolve().parent.parent


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reconflow",
        description="Authorized-scope recon pipeline. Dry-run by default; no network tools run unless --run is given.",
    )
    p.add_argument("--scope", default=str(ROOT / "examples" / "scope.example.json"), help="JSON scope file")
    p.add_argument("--target", required=True, help="exact root domain or IP listed in the scope file")
    p.add_argument("--run", action="store_true", help="execute tools; otherwise only print the plan")
    p.add_argument("--i-have-authorization", action="store_true", help="required with --run; confirm written authorization")
    p.add_argument("--tools", default=",".join(DEFAULT_TOOLS), help="comma-separated tools: subfinder,httpx,nmap,nuclei,katana,ffuf")
    p.add_argument("--ffuf-url", help="exact in-scope base URL to fuzz; required if ffuf selected")
    p.add_argument("--enable-sqlmap", action="store_true", help="separately opt into low-risk SQLMap on exact scope.sqlmap_urls")
    p.add_argument("--out", default=str(ROOT / "runs"), help="local output directory (default: runs/)")
    return p


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        scope = load_scope(args.scope)
        tools = tuple(x.strip() for x in args.tools.split(",") if x.strip())
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        target_slug = re.sub(r"[^A-Za-z0-9_-]", "_", args.target)
        run_dir = Path(args.out) / (timestamp + "-" + target_slug)
        result = run_pipeline(
            scope, args.target, run_dir,
            dry_run=not args.run,
            consent=args.i_have_authorization,
            tools=tools,
            ffuf_url=args.ffuf_url,
            enable_sqlmap=args.enable_sqlmap,
        )
        print(f"ReconFlow {result['run_id']} — {result['status']} — target {result['target']}")
        for stage in result["stages"]:
            argv = " ".join(shlex.quote(part) for part in stage["argv"])
            print(f"[{stage['status']}] {stage['name']}: {argv}")
        if result.get("missing_tools"):
            print("Missing tools:", ", ".join(result["missing_tools"]), file=sys.stderr)
            return 2
        if result.get("wrong_tools"):
            for name, reason in result["wrong_tools"].items():
                print(f"Wrong executable for {name}: {reason}", file=sys.stderr)
            return 2
        if args.run and not args.i_have_authorization:
            return 2
        if result.get("status") == "failed":
            print("Pipeline stopped. Review the local manifest and stage stderr.", file=sys.stderr)
            return 1
        if args.run:
            print("Artifacts:", run_dir)
        else:
            print("Dry-run only. Add --run and --i-have-authorization only for a scope you are authorized to test.")
        return 0
    except (ScopeError, OSError, json.JSONDecodeError) as exc:
        print(f"reconflow: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
