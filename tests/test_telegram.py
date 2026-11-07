import os
import unittest
from unittest.mock import patch

from reconflow.telegram import notify_status


class TelegramTests(unittest.TestCase):
    def test_missing_credentials_never_sends(self):
        with patch.dict(os.environ, {}, clear=True), patch("reconflow.telegram.urlopen") as opener:
            self.assertFalse(notify_status("run started"))
        opener.assert_not_called()

    def test_sends_short_status_using_environment_credentials(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self): return b'{"ok":true}'
        def fake_open(req, timeout):
            self.assertEqual(timeout, 5)
            self.assertIn("/bottest-token/sendMessage", req.full_url)
            body = req.data.decode()
            self.assertIn("chat_id=123", body)
            self.assertNotIn("target.example", body)
            return Response()
        with patch.dict(os.environ, {"RECONFLOW_TELEGRAM_BOT_TOKEN":"test-token", "RECONFLOW_TELEGRAM_CHAT_ID":"123"}, clear=True):
            self.assertTrue(notify_status("run abc123: nmap completed", opener=fake_open))

    def test_transport_error_is_non_fatal(self):
        def fail(*args, **kwargs): raise OSError("network down")
        with patch.dict(os.environ, {"RECONFLOW_TELEGRAM_BOT_TOKEN":"test-token", "RECONFLOW_TELEGRAM_CHAT_ID":"123"}, clear=True):
            self.assertFalse(notify_status("run started", opener=fail))


if __name__ == "__main__":
    unittest.main()
