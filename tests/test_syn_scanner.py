"""Tests for scan timing profiles and bounded SYN validation."""

import unittest

from nightrecon_red_engine.scan_profiles import get_scan_timing_profile
from nightrecon_red_engine.syn_scanner import MAX_SYN_PORTS_PER_SCAN
from nightrecon_shared_core.authorization import Scope


class ScanProfileTests(unittest.TestCase):
    def test_named_profiles_are_bounded(self):
        polite = get_scan_timing_profile("polite")
        normal = get_scan_timing_profile("normal")
        fast = get_scan_timing_profile("fast")
        self.assertLess(polite.max_probes_per_second, normal.max_probes_per_second)
        self.assertLess(normal.max_probes_per_second, fast.max_probes_per_second)

    def test_unknown_profile_is_rejected(self):
        with self.assertRaises(ValueError):
            get_scan_timing_profile("stealth")


class SynScannerValidationTests(unittest.TestCase):
    def test_scope_model_authorizes_literal_ip(self):
        scope = Scope.from_values(["192.0.2.0/24"])
        self.assertTrue(scope.is_authorized(__import__(
            "nightrecon_shared_core.authorization",
            fromlist=["parse_target"],
        ).parse_target("192.0.2.10")))

    def test_syn_port_ceiling_is_bounded(self):
        self.assertLessEqual(MAX_SYN_PORTS_PER_SCAN, 4096)


if __name__ == "__main__":
    unittest.main()
