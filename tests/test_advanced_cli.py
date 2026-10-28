"""Tests for advanced operator CLI parser surfaces."""

import unittest

from nightrecon_red_engine.advanced_cli import build_parser


class AdvancedCliTests(unittest.TestCase):
    def test_syn_scan_parser_accepts_profile(self):
        args = build_parser().parse_args((
            "syn-scan",
            "192.0.2.10",
            "--scope",
            "192.0.2.0/24",
            "--ports",
            "22,80,443",
            "--profile",
            "polite",
        ))
        self.assertEqual(args.command, "syn-scan")
        self.assertEqual(args.profile, "polite")

    def test_packet_analyze_parser(self):
        args = build_parser().parse_args((
            "packet",
            "analyze",
            "capture.pcap",
            "--protocol",
            "dns",
        ))
        self.assertEqual(args.packet_command, "analyze")
        self.assertEqual(args.protocol, "dns")

    def test_web_proxy_requires_scope(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args(("web-proxy",))


if __name__ == "__main__":
    unittest.main()
