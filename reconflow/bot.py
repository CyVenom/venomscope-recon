"""Allowlisted Telegram command interface for a fixed, pre-authorized scan scope."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .commands import DEFAULT_TOOLS, build_plan
from .runner import run_pipeline
from .scope import ScopeError, load_scope, validate_root

HELP_TEXT = (
    "ReconFlow commands:\n"
    "/status — check whether the bot is idle or scanning\n"
    "/lastscan — summarize the latest saved run\n"
    "/scan — run the configured scope (no target arguments)\n"
    "/help — show this help\n\n"
    "Only the configured chat can control this bot. /scan runs network tools against the saved scope."
)
COMMAND_RE = re.compile(r"^/([a-zA-Z0-9_]+)(?:@[a-zA-Z0-9_]+)?(?:\s+(.*))?$", re.DOTALL)


def _default_start_worker(fn):
    threading.Thread(target=fn, name="reconflow-scan", daemon=True).start()


class BotController:
    """Handle commands from one exact Telegram chat; target/scope are fixed at startup."""

    def __init__(self, *, scope, target, runs_dir, allowed_chat_id, scanner, send_message, start_worker=_default_start_worker, tools=DEFAULT_TOOLS):
        if not str(allowed_chat_id).strip():
            raise ScopeError("a Telegram chat ID allowlist is required")
        if scope.get("template", False):
            raise ScopeError("the example/template scope cannot be used by the Telegram bot")
        self.scope = scope
        self.target = validate_root(target, scope)
        self.runs_dir = Path(runs_dir)
        self.allowed_chat_id = str(allowed_chat_id).strip()
        self.scanner = scanner
        self.send_message = send_message
        self.start_worker = start_worker
        self.tools = tuple(tools)
        self._lock = threading.Lock()
        self._running = False
        # Validate the fixed tool plan before polling Telegram.
        build_plan(self.target, self.scope, self.runs_dir / "plan", tools=self.tools)

    @property
    def running(self):
        with self._lock:
            return self._running

    def _send(self, text):
        try:
            self.send_message(self.allowed_chat_id, text[:3500])
        except Exception:
            # Polling/scan state must not crash because a notification request failed.
            pass

    def _last_scan(self):
        manifests = list(self.runs_dir.glob("*/manifest.json")) if self.runs_dir.exists() else []
        manifests.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        for path in manifests:
            try:
                data = json.loads(path.read_text(encoding="utf8"))
                stages = data.get("stages", [])
                summary = ", ".join(f"{s.get('name', 'stage')}: {s.get('status', 'unknown')}" for s in stages[:8])
                return f"Latest run {data.get('run_id', 'unknown')}: {data.get('status', 'unknown')}" + (f"\n{summary}" if summary else "")
            except (OSError, json.JSONDecodeError, TypeError):
                continue
        return "No saved scans yet. Use /scan to run the configured scope."

    def _run_scan(self):
        try:
            result = self.scanner(self.scope, self.target, self.runs_dir, self.tools)
            status = result.get("status", "unknown")
            run_id = result.get("run_id", "unknown")
            stages = result.get("stages", [])
            details = ", ".join(f"{s.get('name', 'stage')}: {s.get('status', 'unknown')}" for s in stages[:8])
            text = f"Scan {status} (run {run_id})." + (f"\n{details}" if details else "")
            missing = result.get("missing_tools", [])
            if missing:
                text += "\nMissing tools: " + ", ".join(str(x) for x in missing)
            wrong = result.get("wrong_tools", {})
            if wrong:
                text += "\nTool check failed: " + ", ".join(str(x) for x in wrong)
            self._send(text)
        except Exception:
            # Never send exception text or raw tool output to Telegram.
            self._send("Scan failed before completion. Check the local ReconFlow logs.")
        finally:
            with self._lock:
                self._running = False

    def process_update(self, update: dict) -> bool:
        message = update.get("message") or {}
        chat = message.get("chat") or {}
        sender = message.get("from") or {}
        if chat.get("type") != "private":
            return False
        if str(chat.get("id", "")) != self.allowed_chat_id or str(sender.get("id", "")) != self.allowed_chat_id:
            return False
        text = message.get("text")
        if not isinstance(text, str):
            return False
        match = COMMAND_RE.fullmatch(text.strip())
        if not match:
            return False
        command, arguments = match.group(1).lower(), (match.group(2) or "").strip()
        if command == "start":
            # Users may need to open the bot with /start once, but it is not exposed in the menu.
            return True
        if command == "help":
            self._send(HELP_TEXT)
        elif command == "status":
            self._send("ReconFlow bot is online. Scan status: " + ("running" if self.running else "idle") + ".")
        elif command == "lastscan":
            self._send(self._last_scan())
        elif command == "scan":
            if arguments:
                self._send("Use /scan without arguments. The bot only scans its configured scope and target.")
                return True
            with self._lock:
                if self._running:
                    self._send("A scan is already running.")
                    return True
                self._running = True
            self._send("Scan queued for the configured scope. Only authorized targets will be scanned.")
            try:
                self.start_worker(self._run_scan)
            except Exception:
                with self._lock:
                    self._running = False
                self._send("Could not start the scan worker. Check the local ReconFlow logs.")
        else:
            self._send("Unknown command. Use /help.")
        return True


def telegram_api(token: str, method: str, params: dict | None = None, *, opener=urllib.request.urlopen):
    """Call Telegram Bot API without printing or surfacing the token in errors."""
    data = urllib.parse.urlencode(params or {}).encode("utf8")
    request = urllib.request.Request(
        "https://api.telegram.org/bot" + token + "/" + method,
        data=data if data else None,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with opener(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf8"))
    except Exception as exc:
        raise RuntimeError("Telegram API request failed") from None
    if not payload.get("ok"):
        raise RuntimeError("Telegram API returned an error")
    return payload.get("result")


def poll_once(controller: BotController, token: str, offset: int = 0, *, api_call=telegram_api) -> int:
    updates = api_call(token, "getUpdates", {"offset": offset, "timeout": 20, "allowed_updates": json.dumps(["message"])})
    next_offset = offset
    for update in updates or []:
        next_offset = max(next_offset, int(update.get("update_id", -1)) + 1)
        controller.process_update(update)
    return next_offset


def poll_forever(controller: BotController, token: str, *, api_call=telegram_api, sleep=time.sleep):
    offset = 0
    while True:
        try:
            offset = poll_once(controller, token, offset, api_call=api_call)
        except KeyboardInterrupt:
            return
        except Exception:
            # Do not print API error details; they can include a URL with the bot token.
            sleep(3)


def _scan_callable(scope, target, runs_dir, tools):
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    slug = re.sub(r"[^A-Za-z0-9_-]", "_", target)
    return run_pipeline(
        scope, target, Path(runs_dir) / f"{timestamp}-{slug}",
        dry_run=False, consent=True, tools=tools,
    )


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="python -m reconflow.bot", description="Run the allowlisted ReconFlow Telegram command bot.")
    parser.add_argument("--scope", required=True, help="non-template JSON scope file")
    parser.add_argument("--target", required=True, help="exact root from the scope file; Telegram cannot change it")
    parser.add_argument("--runs", default="runs", help="local run artifact folder")
    parser.add_argument("--i-have-authorization", action="store_true", help="confirm written authorization for this fixed scope")
    args = parser.parse_args(argv)
    token = os.environ.get("RECONFLOW_TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("RECONFLOW_TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        print("Set RECONFLOW_TELEGRAM_BOT_TOKEN and RECONFLOW_TELEGRAM_CHAT_ID in this terminal first.", file=sys.stderr)
        return 2
    if not args.i_have_authorization:
        print("Starting a command bot that can scan requires --i-have-authorization.", file=sys.stderr)
        return 2
    try:
        scope = load_scope(args.scope)
        if scope.get("template", False):
            raise ScopeError("the template scope cannot be used by the bot")
        target = validate_root(args.target, scope)
        controller = BotController(
            scope=scope, target=target, runs_dir=args.runs, allowed_chat_id=chat_id,
            scanner=_scan_callable,
            send_message=lambda dest, text: telegram_api(token, "sendMessage", {"chat_id": dest, "text": text, "disable_web_page_preview": "true"}),
        )
    except (OSError, ScopeError, ValueError) as exc:
        print(f"reconflow bot: {exc}", file=sys.stderr)
        return 2
    try:
        telegram_api(token, "sendMessage", {"chat_id": chat_id, "text": "ReconFlow command bot online. Use /help."})
    except RuntimeError:
        print("Could not contact Telegram. Check the bot token and network.", file=sys.stderr)
        return 2
    print("ReconFlow Telegram bot is polling the allowlisted chat. Ctrl+C to stop.")
    poll_forever(controller, token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
