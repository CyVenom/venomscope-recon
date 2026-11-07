import json
import tempfile
import unittest
from pathlib import Path

from reconflow.bot import BotController, poll_once, telegram_api


class BotControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.runs = Path(self.tmp.name) / "runs"
        self.scope = {
            "project":"authorized test", "authorized_by":"user", "expires":"2099-12-31",
            "template":False, "root_domains":["example.com"], "allowed_ips":[],
            "excluded_hosts":[], "sqlmap_urls":[], "nmap_ports":[443],
            "max_hosts":10, "rate_limit":1,
        }
        self.sent = []
        self.workers = []
        self.scans = []
        self.bot = BotController(
            scope=self.scope,
            target="example.com",
            runs_dir=self.runs,
            allowed_chat_id="100200300",
            scanner=self.fake_scan,
            send_message=lambda chat_id, text: self.sent.append((str(chat_id), text)),
            start_worker=self.workers.append,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def update(self, text, chat_id="100200300", sender_id=None, chat_type="private"):
        sender_id = chat_id if sender_id is None else sender_id
        return {"message":{"chat":{"id":chat_id,"type":chat_type},"from":{"id":sender_id},"text":text}}

    def fake_scan(self, scope, target, runs_dir, tools):
        self.scans.append((scope, target, runs_dir, tools))
        return {"status":"completed", "run_id":"abc123", "stages":[{"name":"nmap","status":"completed"}]}

    def test_help_lists_only_supported_commands_and_no_start(self):
        self.bot.process_update(self.update("/help"))
        text = self.sent[-1][1]
        for name in ("/status", "/lastscan", "/scan", "/help"):
            self.assertIn(name, text)
        self.assertNotIn("/start", text)

    def test_start_is_silent_and_not_a_botfather_menu_command(self):
        self.assertTrue(self.bot.process_update(self.update("/start")))
        self.assertEqual(self.sent, [])
        self.assertEqual(self.scans, [])

    def test_status_reports_bot_and_scan_state(self):
        self.bot.process_update(self.update("/status"))
        self.assertIn("idle", self.sent[-1][1].lower())
        self.assertEqual(self.scans, [])

    def test_unauthorized_chat_is_silent(self):
        self.bot.process_update(self.update("/status", chat_id="999"))
        self.assertEqual(self.sent, [])
        self.assertEqual(self.scans, [])

    def test_group_and_other_sender_are_rejected(self):
        self.bot.process_update(self.update("/scan", chat_type="group"))
        self.bot.process_update(self.update("/scan", sender_id="777"))
        self.assertEqual(self.sent, [])
        self.assertEqual(self.workers, [])

    def test_scan_uses_only_fixed_scope_and_target(self):
        self.bot.process_update(self.update("/scan"))
        self.assertEqual(len(self.workers), 1)
        self.assertEqual(self.scans, [])
        self.workers.pop(0)()
        self.assertEqual(len(self.scans), 1)
        self.assertEqual(self.scans[0][0], self.scope)
        self.assertEqual(self.scans[0][1], "example.com")
        self.assertIn("completed", self.sent[-1][1].lower())

    def test_scan_rejects_user_supplied_target(self):
        self.bot.process_update(self.update("/scan evil.example"))
        self.assertEqual(self.workers, [])
        self.assertEqual(self.scans, [])
        self.assertIn("configured scope", self.sent[-1][1].lower())

    def test_duplicate_scan_is_rejected_while_worker_is_active(self):
        self.bot.process_update(self.update("/scan"))
        self.bot.process_update(self.update("/scan"))
        self.assertEqual(len(self.workers), 1)
        self.assertIn("already running", self.sent[-1][1].lower())
        self.workers.pop(0)()

    def test_lastscan_reports_manifest_summary_without_raw_output(self):
        folder = self.runs / "20261108T010101Z"
        folder.mkdir(parents=True)
        (folder / "manifest.json").write_text(json.dumps({
            "run_id":"prev1", "status":"completed", "started_at":"2026-11-08T01:01:01Z",
            "stages":[{"name":"nmap", "status":"completed"}],
            "secret_output":"never expose this",
        }), encoding="utf8")
        self.bot.process_update(self.update("/lastscan"))
        text = self.sent[-1][1]
        self.assertIn("prev1", text)
        self.assertIn("nmap", text)
        self.assertNotIn("never expose this", text)

    def test_template_scope_is_refused_at_startup(self):
        scope = dict(self.scope, template=True)
        with self.assertRaises(ValueError):
            BotController(
                scope=scope, target="example.com", runs_dir=self.runs,
                allowed_chat_id="100200300", scanner=self.fake_scan,
                send_message=lambda *args: None, start_worker=self.workers.append,
            )

    def test_poll_once_dispatches_updates_and_advances_offset(self):
        calls = []
        def api(token, method, params):
            calls.append((token, method, params))
            return [{"update_id": 41, **self.update("/status")}, {"update_id": 42, **self.update("/help")}]
        offset = poll_once(self.bot, "test-token", 41, api_call=api)
        self.assertEqual(offset, 43)
        self.assertEqual(calls[0][1], "getUpdates")
        self.assertEqual(calls[0][2]["offset"], 41)
        self.assertEqual(len(self.sent), 2)

    def test_telegram_api_uses_post_and_parses_response(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self): return b'{"ok":true,"result":[]}'
        seen = []
        def opener(request, timeout):
            seen.append((request, timeout))
            return Response()
        result = telegram_api("secret-test-token", "getUpdates", {"offset":2}, opener=opener)
        self.assertEqual(result, [])
        self.assertEqual(seen[0][1], 30)
        self.assertIn("getUpdates", seen[0][0].full_url)
        self.assertIn("offset=2", seen[0][0].data.decode())


if __name__ == "__main__":
    unittest.main()
