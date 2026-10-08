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

    def test_packet_deep_analysis_option_is_available(self):
        args = build_parser().parse_args((
            "packet",
            "analyze",
            "capture.pcap",
            "--deep",
        ))
        self.assertTrue(args.deep)

    def test_https_intercept_proxy_option_is_available(self):
        args = build_parser().parse_args((
            "web-proxy",
            "--scope",
            "example.test",
            "--https-intercept",
        ))
        self.assertTrue(args.https_intercept)

    def test_validation_module_and_range_commands_parse(self):
        validation = build_parser().parse_args(("validation-modules",))
        self.assertEqual(validation.command, "validation-modules")

        range_args = build_parser().parse_args((
            "range-sim",
            "--host",
            "operator:compromised:privileged",
            "--host",
            "server",
            "--step",
            "lateral-movement:operator:server",
        ))
        self.assertEqual(range_args.command, "range-sim")
        self.assertEqual(len(range_args.host), 2)


if __name__ == "__main__":
    unittest.main()
