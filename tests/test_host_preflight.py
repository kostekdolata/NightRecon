"""Passive host preflight and least-data tool routing tests."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon_red_engine.host_preflight import (
    collect_host_preflight, route_host_context,
)
from nightrecon_red_engine.network_environment import (
    NetworkEnvironmentSnapshot, NetworkInterface, RouteEntry,
)
from nightrecon_red_engine.red_cli import main as public_red_main
from nightrecon_shared_core.editions import available_commands


class HostPreflightTests(unittest.TestCase):
    def _snapshot(self):
        return NetworkEnvironmentSnapshot(
            interfaces=(
                NetworkInterface("eth0", 2), NetworkInterface("vpn0", 4),
            ),
            routes=(
                RouteEntry("192.0.2.0/24", "", "eth0", 10),
                RouteEntry("198.51.100.0/24", "192.0.2.1", "vpn0", 20),
            ),
            default_routes=(), collection_errors=(),
        )

    def test_passive_inventory_and_no_implicit_scan_scope(self):
        with tempfile.TemporaryDirectory() as folder:
            approved_looking_path = Path(folder) / "nmap"
            approved_looking_path.write_bytes(b"never execute this fixture")
            def find(executable):
                return str(approved_looking_path) if executable == "nmap" else None
            with patch(
                "nightrecon_red_engine.host_preflight.collect_network_environment",
                return_value=self._snapshot(),
            ), patch(
                "nightrecon_red_engine.host_preflight.shutil.which",
                side_effect=find,
            ), patch(
                "nightrecon_red_engine.host_preflight.platform.system",
                return_value="Linux",
            ), patch(
                "nightrecon_red_engine.host_preflight.platform.machine",
                return_value="x86_64",
            ):
                report = collect_host_preflight().as_dict()
        self.assertEqual(len(report["interfaces"]), 2)
        self.assertEqual(report["routes"][1]["gateway"], "192.0.2.1")
        self.assertFalse(report["scope_authorisation_inferred"])
        self.assertFalse(report["network_scan_performed"])
        by_tool = {t["tool"]: t for t in report["tools"]}
        self.assertEqual(by_tool["nmap"]["state"], "unverified-present")
        self.assertFalse(by_tool["nmap"]["trusted_for_execution"])
        self.assertEqual(by_tool["nuclei"]["state"], "missing")

    def test_context_is_filtered_for_each_tool(self):
        with patch(
            "nightrecon_red_engine.host_preflight.collect_network_environment",
            return_value=self._snapshot(),
        ), patch("nightrecon_red_engine.host_preflight.shutil.which", return_value=None):
            snapshot = collect_host_preflight()
        nmap = route_host_context(snapshot, "nmap")
        tshark = route_host_context(snapshot, "tshark")
        zap = route_host_context(snapshot, "zap")
        self.assertIn("routes", nmap)
        self.assertNotIn("routes", tshark)
        self.assertNotIn("interfaces", zap)
        self.assertEqual(zap["local_service_configuration"], "not-probed")
        self.assertEqual(nmap["authorised_targets"], [])
        self.assertFalse(nmap["execution_approval"])
        self.assertNotIn("tools", json.dumps(zap))
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            route_host_context(snapshot, "arbitrary-exploit")

    def test_unavailable_network_returns_explicit_error(self):
        with patch(
            "nightrecon_red_engine.host_preflight.collect_network_environment",
            side_effect=OSError("secret path should not leak"),
        ), patch("nightrecon_red_engine.host_preflight.shutil.which", return_value=None):
            report = collect_host_preflight().as_dict()
        self.assertEqual(report["interfaces"], [])
        self.assertEqual(report["routes"], [])
        self.assertEqual(report["errors"], ["Local network inventory unavailable: OSError"])
        self.assertNotIn("secret path", json.dumps(report))

    def test_public_host_preflight_command_has_no_scan_side_effect(self):
        self.assertIn("host-preflight", available_commands("red"))
        with patch(
            "nightrecon_red_engine.host_preflight.collect_network_environment",
            return_value=self._snapshot(),
        ), patch("nightrecon_red_engine.host_preflight.shutil.which", return_value=None):
            with contextlib.redirect_stdout(io.StringIO()) as output:
                public_red_main(("host-preflight", "--consumer", "nuclei"))
        result = json.loads(output.getvalue())
        self.assertEqual(result["consumer"], "nuclei")
        self.assertEqual(result["authorised_targets"], [])
        self.assertFalse(result["execution_approval"])
        self.assertNotIn("interfaces", result)


if __name__ == "__main__":
    unittest.main()
