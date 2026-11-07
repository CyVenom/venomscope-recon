"""Preflight checks for missing tools and the common Python/ProjectDiscovery httpx clash."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path


def preflight_tools(tools, *, which=shutil.which, run=subprocess.run) -> dict:
    missing, wrong = [], {}
    for name in sorted(set(tools)):
        executable = which(name)
        if not executable:
            missing.append(name)
            continue
        if name == "httpx":
            try:
                result = run([executable, "--help"], shell=False, capture_output=True, text=True, timeout=8, check=False)
                help_text = ((result.stdout or "") + "\n" + (result.stderr or "")).lower()
            except (OSError, subprocess.TimeoutExpired):
                help_text = ""
            if "-list" not in help_text or "-json" not in help_text:
                wrong[name] = "not the ProjectDiscovery httpx CLI"
    return {"missing": missing, "wrong": wrong}
