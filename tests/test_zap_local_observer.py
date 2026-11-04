"""Read-only ZAP API and operator entrypoint regressions (no network)."""
import contextlib
import io
import json
import os
import unittest
from unittest.mock import patch

from nightrecon_red_engine.red_cli import main as public_red_main
from nightrecon_red_engine.zap_local_observer import inspect_local_zap
from nightrecon_shared_core.editions import available_commands


class FakeResponse:
    def __init__(self, value):
        self.status = 200
        self.value = json.dumps(value).encode("utf-8")
    def read(self, size):
        return self.value[:size]


class FakeConnection:
    def __init__(self, host, port, timeout):
        self.host, self.port, self.timeout = host, port, timeout
        self.calls = []
    def request(self, method, path, headers):
        self.calls.append((method, path, headers))
    def getresponse(self):
        if self.calls[-1][1].endswith("version/"):
            return FakeResponse({"version": "2.16.1"})
        return FakeResponse({"sites": ["https://private.invalid", "https://other.invalid"]})
    def close(self):
        pass


class ZapLocalObserverTests(unittest.TestCase):
    def test_local_fixed_read_only_api_and_redacted_summary(self):
        with patch(
            "nightrecon_red_engine.zap_local_observer.http.client.HTTPConnection",
            FakeConnection,
        ) as factory:
            result = inspect_local_zap(port=8090, api_key="LOCAL-SECRET")
        self.assertEqual(result.version, "2.16.1")
        self.assertEqual(result.site_count, 2)
        report = result.operator_report()
        self.assertFalse(report["scan_started"])
        self.assertEqual(report["api_calls"], ("core/view/version", "core/view/sites"))
        self.assertNotIn("LOCAL-SECRET", json.dumps(report))
        self.assertNotIn("private.invalid", json.dumps(report))
        self.assertEqual(report["execution_status"], "succeeded")

    def test_api_key_required_and_no_connection(self):
        with patch("nightrecon_red_engine.zap_local_observer.http.client.HTTPConnection") as connection:
            with self.assertRaises(PermissionError):
                inspect_local_zap(api_key="")
            connection.assert_not_called()

    def test_port_and_key_header_restrictions(self):
        for port in (0, 65536, True):
            with self.assertRaises(ValueError):
                inspect_local_zap(port=port, api_key="secret")
        with self.assertRaises(PermissionError):
            inspect_local_zap(api_key="bad\\r\\nInjected: 1")

    def test_public_cli_requires_opt_in_and_secret_environment(self):
        self.assertIn("zap-local-status", available_commands("red"))
        with patch.dict(os.environ, {"RED_NIGHT_ZAP_API_KEY": "secret"}):
            with self.assertRaisesRegex(PermissionError, "--connect"):
                public_red_main(("zap-local-status",))
        with patch.dict(os.environ, {"RED_NIGHT_ZAP_API_KEY": ""}):
            with self.assertRaisesRegex(PermissionError, "RED_NIGHT_ZAP_API_KEY"):
                public_red_main(("zap-local-status", "--connect"))

    def test_public_cli_calls_fixed_status_and_prints_report(self):
        with patch.dict(os.environ, {"RED_NIGHT_ZAP_API_KEY": "secret"}), patch(
            "nightrecon_red_engine.zap_local_observer.http.client.HTTPConnection",
            FakeConnection,
        ), contextlib.redirect_stdout(io.StringIO()) as output:
            public_red_main(("zap-local-status", "--port", "8090", "--connect"))
        report = json.loads(output.getvalue())
        self.assertEqual(report["tool"], "owasp-zap")
        self.assertEqual(report["tool_version"], "2.16.1")
        self.assertEqual(report["observed_site_count"], 2)


if __name__ == "__main__":
    unittest.main()
