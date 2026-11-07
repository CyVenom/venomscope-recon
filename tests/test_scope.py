import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from reconflow.scope import ScopeError, filter_hosts, in_scope_host, load_scope, validate_root


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "scope.json"
        self.payload = {
            "project": "authorized lab",
            "authorized_by": "0xCybervenom",
            "expires": "2099-12-31",
            "root_domains": ["example.com"],
            "allowed_ips": ["127.0.0.1"],
            "excluded_hosts": ["private.example.com"],
            "sqlmap_urls": ["http://app.example.com/item?id=1"],
            "nmap_ports": [80, 443, 8080],
            "max_hosts": 50,
            "rate_limit": 2,
        }
        self.write()

    def tearDown(self):
        self.tmp.cleanup()

    def write(self):
        self.path.write_text(json.dumps(self.payload), encoding="utf8")

    def test_accepts_in_scope_subdomain_but_not_suffix_spoof(self):
        scope = load_scope(self.path, today=date(2026, 1, 1))
        self.assertTrue(in_scope_host("api.example.com", scope))
        self.assertFalse(in_scope_host("example.com.attacker.test", scope))

    def test_excluded_host_excludes_its_children(self):
        scope = load_scope(self.path, today=date(2026, 1, 1))
        self.assertFalse(in_scope_host("private.example.com", scope))
        self.assertFalse(in_scope_host("x.private.example.com", scope))

    def test_filters_discovered_hosts_and_deduplicates(self):
        scope = load_scope(self.path, today=date(2026, 1, 1))
        result = filter_hosts(["api.example.com", "api.example.com", "x.private.example.com", "evil.test"], scope)
        self.assertEqual(result, ["api.example.com"])

    def test_discovery_is_capped_by_scope_max_hosts(self):
        self.payload["max_hosts"] = 2
        self.write()
        scope = load_scope(self.path, today=date(2026, 1, 1))
        result = filter_hosts(["z.example.com", "a.example.com", "m.example.com"], scope)
        self.assertEqual(result, ["a.example.com", "m.example.com"])

    def test_invalid_max_hosts_is_rejected(self):
        self.payload["max_hosts"] = 0
        self.write()
        with self.assertRaises(ScopeError):
            load_scope(self.path, today=date(2026, 1, 1))

    def test_root_must_be_exact_scope_entry(self):
        scope = load_scope(self.path, today=date(2026, 1, 1))
        self.assertEqual(validate_root("example.com", scope), "example.com")
        with self.assertRaises(ScopeError):
            validate_root("sub.example.com", scope)

    def test_wildcard_scope_is_rejected(self):
        self.payload["root_domains"] = ["*.example.com"]
        self.write()
        with self.assertRaises(ScopeError):
            load_scope(self.path, today=date(2026, 1, 1))

    def test_expired_scope_is_rejected(self):
        self.payload["expires"] = "2025-01-01"
        self.write()
        with self.assertRaises(ScopeError):
            load_scope(self.path, today=date(2026, 1, 1))

    def test_ip_must_be_explicitly_listed(self):
        scope = load_scope(self.path, today=date(2026, 1, 1))
        self.assertTrue(in_scope_host("127.0.0.1", scope))
        self.assertFalse(in_scope_host("127.0.0.2", scope))

    def test_ip_only_local_scope_is_valid(self):
        self.payload["root_domains"] = []
        self.payload["allowed_ips"] = ["127.0.0.1"]
        self.payload["sqlmap_urls"] = []
        self.write()
        scope = load_scope(self.path, today=date(2026, 1, 1))
        self.assertEqual(validate_root("127.0.0.1", scope), "127.0.0.1")

    def test_ipv6_is_supported_as_an_exact_allowed_address(self):
        self.payload["root_domains"] = []
        self.payload["allowed_ips"] = ["::1"]
        self.payload["sqlmap_urls"] = []
        self.write()
        scope = load_scope(self.path, today=date(2026, 1, 1))
        self.assertTrue(in_scope_host("::1", scope))
        self.assertFalse(in_scope_host("::2", scope))

    def test_template_scope_cannot_run_real_tools(self):
        from reconflow.runner import run_pipeline
        from unittest.mock import patch
        self.payload["template"] = True
        self.write()
        scope = load_scope(self.path, today=date(2026, 1, 1))
        with patch("reconflow.runner.subprocess.run") as run:
            with self.assertRaises(ScopeError):
                run_pipeline(scope, "example.com", Path(self.tmp.name) / "run", dry_run=False, consent=True, tools=("subfinder",))
        run.assert_not_called()

    def test_template_marker_must_be_boolean(self):
        self.payload["template"] = "false"
        self.write()
        with self.assertRaises(ScopeError):
            load_scope(self.path, today=date(2026, 1, 1))

    def test_sqlmap_opt_in_requires_at_least_one_exact_url(self):
        from reconflow.commands import build_plan
        scope = load_scope(self.path, today=date(2026, 1, 1))
        scope["sqlmap_urls"] = []
        with self.assertRaises(ScopeError):
            build_plan("example.com", scope, Path("run"), tools=("httpx",), enable_sqlmap=True)

    def test_active_template_tools_require_httpx_dependency(self):
        from reconflow.commands import build_plan
        scope = load_scope(self.path, today=date(2026, 1, 1))
        with self.assertRaises(ScopeError):
            build_plan("example.com", scope, Path("run"), tools=("nuclei",))

    def test_sqlmap_requires_separate_opt_in(self):
        from reconflow.commands import build_plan
        scope = load_scope(self.path, today=date(2026, 1, 1))
        with self.assertRaises(ScopeError):
            build_plan("example.com", scope, Path("run"), tools=("sqlmap",))

    def test_plan_must_contain_at_least_one_applicable_stage(self):
        from reconflow.commands import build_plan
        scope = load_scope(self.path, today=date(2026, 1, 1))
        with self.assertRaises(ScopeError):
            build_plan("example.com", scope, Path("run"), tools=())

    def test_nuclei_excludes_intrusive_oast_and_fuzz_tags(self):
        from reconflow.commands import build_plan
        scope = load_scope(self.path, today=date(2026, 1, 1))
        cmd = next(x["argv"] for x in build_plan("example.com", scope, Path("run")) if x["name"] == "nuclei")
        tags = cmd[cmd.index("-etags") + 1]
        self.assertTrue({"intrusive", "dos", "fuzz", "oast"}.issubset(set(tags.split(","))))
        self.assertIn("low,medium", cmd)
        self.assertIn("2", cmd[cmd.index("-rl") + 1])
        self.assertIn("-dr", cmd)

    def test_katana_is_opt_in_and_restricted_to_each_fqdn(self):
        from reconflow.commands import DEFAULT_TOOLS, build_plan
        scope = load_scope(self.path, today=date(2026, 1, 1))
        self.assertNotIn("katana", DEFAULT_TOOLS)
        cmd = next(x["argv"] for x in build_plan("example.com", scope, Path("run"), tools=("httpx", "katana")) if x["name"] == "katana")
        self.assertEqual(cmd[cmd.index("-fs") + 1], "fqdn")

    def test_nmap_port_list_is_explicit_and_validated(self):
        self.payload["nmap_ports"] = [0]
        self.write()
        with self.assertRaises(ScopeError):
            load_scope(self.path, today=date(2026, 1, 1))

    def test_nmap_uses_explicit_bounded_port_list(self):
        from reconflow.commands import build_plan
        scope = load_scope(self.path, today=date(2026, 1, 1))
        cmd = next(x["argv"] for x in build_plan("example.com", scope, Path("run"), tools=("nmap",)) if x["name"] == "nmap")
        self.assertEqual(cmd[cmd.index("-p") + 1], "80,443,8080")
        self.assertNotIn("--top-ports", cmd)
        self.assertIn("-sT", cmd)
        self.assertIn("--version-light", cmd)
        self.assertIn("-T2", cmd)

    def test_ffuf_is_rate_and_time_bounded_to_in_scope_url(self):
        from reconflow.commands import build_plan
        scope = load_scope(self.path, today=date(2026, 1, 1))
        cmd = next(x["argv"] for x in build_plan("example.com", scope, Path("run"), tools=("ffuf",), ffuf_url="https://app.example.com") if x["name"] == "ffuf")
        self.assertEqual(cmd[cmd.index("-rate") + 1], "2")
        self.assertEqual(cmd[cmd.index("-maxtime") + 1], "30")
        self.assertIn("/FUZZ", cmd[cmd.index("-u") + 1])
        with self.assertRaises(ScopeError):
            build_plan("example.com", scope, Path("run"), tools=("ffuf",), ffuf_url="https://evil.test")

    def test_sqlmap_url_must_be_exactly_allowlisted(self):
        scope = load_scope(self.path, today=date(2026, 1, 1))
        from reconflow.commands import build_sqlmap_command
        cmd = build_sqlmap_command("http://app.example.com/item?id=1", scope, Path("run"))
        self.assertIn("--risk=1", cmd)
        self.assertIn("--technique=BEU", cmd)
        self.assertNotIn("--dump", cmd)
        with self.assertRaises(ScopeError):
            build_sqlmap_command("http://app.example.com/item?id=2", scope, Path("run"))

    def test_dry_run_does_not_execute_any_child_process(self):
        from reconflow.runner import run_pipeline
        from unittest.mock import patch
        scope = load_scope(self.path, today=date(2026, 1, 1))
        with patch("reconflow.runner.subprocess.run") as run:
            result = run_pipeline(scope, "example.com", Path("run"), dry_run=True)
        run.assert_not_called()
        self.assertEqual(result["status"], "dry-run")
        self.assertGreaterEqual(len(result["stages"]), 4)

    def test_real_run_requires_explicit_authorization_acknowledgement(self):
        from reconflow.runner import run_pipeline
        from unittest.mock import patch
        scope = load_scope(self.path, today=date(2026, 1, 1))
        with patch("reconflow.runner.subprocess.run") as run:
            with self.assertRaises(ScopeError):
                run_pipeline(scope, "example.com", Path("run"), dry_run=False, consent=False)
        run.assert_not_called()

    def test_live_pipeline_scope_filters_discovery_before_active_tools(self):
        from reconflow.runner import run_pipeline
        from unittest.mock import patch
        scope = load_scope(self.path, today=date(2026, 1, 1))
        seen = []
        def fake_run(argv, **kwargs):
            seen.append(list(argv))
            if argv[0] == "subfinder":
                out = Path(argv[argv.index("-o") + 1])
                out.write_text("api.example.com\nx.private.example.com\nexample.com.attacker.test\n", encoding="utf8")
            elif argv[0] == "httpx":
                hosts = Path(argv[argv.index("-l") + 1]).read_text(encoding="utf8").splitlines()
                self.assertEqual(hosts, ["api.example.com", "example.com"])
                out = Path(argv[argv.index("-o") + 1])
                out.write_text(json.dumps({"url":"https://api.example.com", "host":"api.example.com"}) + "\\n", encoding="utf8")
            return type("Result", (), {"returncode":0, "stdout":"", "stderr":""})()
        with patch("reconflow.runner.preflight_tools", return_value={"missing":[], "wrong":{}}), patch("reconflow.runner.subprocess.run", side_effect=fake_run):
            result = run_pipeline(scope, "example.com", Path(self.tmp.name) / "run", dry_run=False, consent=True, tools=("subfinder", "httpx"))
        self.assertEqual(result["status"], "completed")
        self.assertEqual([x[0] for x in seen], ["subfinder", "httpx"])
        self.assertEqual(Path(self.tmp.name, "run", "scoped_hosts.txt").read_text(encoding="utf8").splitlines(), ["api.example.com", "example.com"])


if __name__ == "__main__":
    unittest.main()
