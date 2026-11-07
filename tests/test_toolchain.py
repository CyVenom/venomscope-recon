import unittest
from unittest.mock import call

from reconflow.toolchain import preflight_tools


class ToolchainTests(unittest.TestCase):
    def test_rejects_python_httpx_that_is_not_projectdiscovery(self):
        def fake_run(argv, **kwargs):
            return type("Result", (), {"stdout":"Usage: httpx.EXE [OPTIONS] URL", "stderr":"", "returncode":2})()
        result = preflight_tools(["httpx"], which=lambda _: "C:/Python/Scripts/httpx.exe", run=fake_run)
        self.assertEqual(result["wrong"], {"httpx":"not the ProjectDiscovery httpx CLI"})

    def test_accepts_projectdiscovery_httpx_by_help_signature(self):
        seen = []
        def fake_run(argv, **kwargs):
            seen.append((argv, kwargs))
            return type("Result", (), {"stdout":"httpx is a fast toolkit\n-list string input file\n-json output JSONL", "stderr":"", "returncode":0})()
        result = preflight_tools(["httpx"], which=lambda _: "C:/tools/httpx.exe", run=fake_run)
        self.assertEqual(result, {"missing":[], "wrong":{}})
        self.assertEqual(seen[0][0][-1], "--help")
        self.assertFalse(seen[0][1]["shell"])

    def test_missing_tool_is_reported_without_execution(self):
        def fail(*args, **kwargs): raise AssertionError("must not run a missing executable")
        result = preflight_tools(["nmap"], which=lambda _: None, run=fail)
        self.assertEqual(result["missing"], ["nmap"])


if __name__ == "__main__":
    unittest.main()
