"""Status-only Telegram notifications; credentials are read from environment."""
from __future__ import annotations

import json
import os
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def notify_status(message: str, *, opener=urlopen) -> bool:
    token = os.environ.get("RECONFLOW_TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("RECONFLOW_TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        return False
    payload = urlencode({"chat_id": chat_id, "text": message[:300], "disable_web_page_preview": "true"}).encode()
    req = Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with opener(req, timeout=5) as response:
            data = json.loads(response.read().decode("utf8"))
        return data.get("ok") is True
    except Exception:
        return False
