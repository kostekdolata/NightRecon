"""Local Metasploit read-only RPC adapter tests with a fake TLS transport.

These tests never connect to a running msfrpcd or execute a module.
"""
import contextlib
import io
import json
import os
import unittest
from unittest.mock import patch

from nightrecon_red_engine.metasploit_local_rpc import inspect_local_metasploit
from nightrecon_red_engine.red_cli import main as public_red_main
from nightrecon_shared_core.editions import available_commands


class FakeCodec:
    @staticmethod
    def packb(value, **kwargs):
        return json.dumps(value).encode("utf-8")
    @staticmethod
    def unpackb(value, **kwargs):
        return json.loads(value)


class FakeResponse:
    status = 200
    def __init__(self, data):
        self.data = json.dumps(data).encode("utf-8")
    def read(self, length):
        return self.data[:length]


class FakeTLS:
    latest = None
    def __init__(self, host, port, timeout, context):
        self.host, self.port, self.timeout = host, port, timeout
        self.calls = []
        FakeTLS.latest = self
    def request(self, method, path, body, headers):
        self.calls.append((method, path, json.loads(body), headers))
    def getresponse(self):
        name = self.calls[-1][2][0]
        return FakeResponse({
            "core.version": {"version": "6.4.0-release"},
            "module.auxiliary": {"modules": ["scanner/http/title", "scanner/http/headers"]},
            "module.exploits": {"modules": ["linux/example", "windows/example"]},
        }[name])
    def close(self):
        pass


class MetasploitLocalRpcTests(unittest.TestCase):
    def _patched(self):
        return (
            patch("nightrecon_red_engine.metasploit_local_rpc._codec", return_value=FakeCodec),
            patch("nightrecon_red_engine.metasploit_local_rpc.http.client.HTTPSConnection", FakeTLS),
        )

    def test_only_read_only_methods_over_local_tls(self):
        p1,p2 = self._patched()
        with p1,p2:
            observed = inspect_local_metasploit(token="LONG-SECRET-RPC-TOKEN", port=55553)
        self.assertEqual(observed.version, "6.4.0-release")
        self.assertEqual(observed.exploit_count, 2)
        self.assertEqual(observed.auxiliary_count, 2)
        conn = FakeTLS.latest
        self.assertEqual(conn.host, "127.0.0.1")
        self.assertEqual([item[2][0] for item in conn.calls], [
            "core.version", "module.auxiliary", "module.exploits",
        ])
        self.assertTrue(all(item[0] == "POST" and item[1] == "/api/1.0"
                            for item in conn.calls))
        report = observed.operator_report()
        self.assertEqual(report["modules_executed"], 0)
        self.assertNotIn("LONG-SECRET-RPC-TOKEN", json.dumps(report))
        self.assertNotIn("linux/example", json.dumps(report))

    def test_missing_secret_and_port_error_do_not_connect(self):
        with patch("nightrecon_red_engine.metasploit_local_rpc.http.client.HTTPSConnection") as connection:
            with self.assertRaises(PermissionError):
                inspect_local_metasploit(token="")
            with self.assertRaises(ValueError):
                inspect_local_metasploit(token="LONG-SECRET-RPC-TOKEN", port=0)
            connection.assert_not_called()

    def test_public_operator_requires_explicit_opt_in(self):
        self.assertIn("metasploit-status", available_commands("red"))
        with patch.dict(os.environ, {"RED_NIGHT_METASPLOIT_RPC_TOKEN": "LONG-SECRET-RPC-TOKEN"}):
            with self.assertRaisesRegex(PermissionError, "--connect"):
                public_red_main(("metasploit-status",))
        with patch.dict(os.environ, {"RED_NIGHT_METASPLOIT_RPC_TOKEN": ""}):
            with self.assertRaisesRegex(PermissionError, "RED_NIGHT_METASPLOIT_RPC_TOKEN"):
                public_red_main(("metasploit-status", "--connect"))

    def test_operator_cli_prints_redacted_metadata(self):
        p1,p2 = self._patched()
        with p1,p2,patch.dict(os.environ, {
            "RED_NIGHT_METASPLOIT_RPC_TOKEN": "LONG-SECRET-RPC-TOKEN",
        }), contextlib.redirect_stdout(io.StringIO()) as output:
            public_red_main(("metasploit-status", "--connect"))
        report = json.loads(output.getvalue())
        self.assertEqual(report["tool"], "metasploit-framework")
        self.assertEqual(report["auxiliary_module_count"], 2)
        self.assertEqual(report["modules_executed"], 0)
        self.assertNotIn("LONG-SECRET-RPC-TOKEN", output.getvalue())

    def test_invalid_module_list_cannot_claim_success(self):
        class Corrupt(FakeTLS):
            def getresponse(self):
                if self.calls[-1][2][0] == "module.exploits":
                    return FakeResponse({"modules": {"not": "list"}})
                return super().getresponse()
        with patch("nightrecon_red_engine.metasploit_local_rpc._codec", return_value=FakeCodec),patch(
            "nightrecon_red_engine.metasploit_local_rpc.http.client.HTTPSConnection", Corrupt
        ):
            with self.assertRaisesRegex(ValueError, "module inventory"):
                inspect_local_metasploit(token="LONG-SECRET-RPC-TOKEN")


if __name__ == "__main__":
    unittest.main()
