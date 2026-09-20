"""Tests for NightRecon TCP port parsing."""

import unittest

from nightrecon.ports import parse_ports


class PortParsingTests(unittest.TestCase):
    def test_single_port(self):
        self.assertEqual(parse_ports("443"), (443,))

    def test_multiple_ports(self):
        self.assertEqual(
            parse_ports("22,80,443"),
            (22, 80, 443),
        )

    def test_port_range(self):
        self.assertEqual(
            parse_ports("20-23"),
            (20, 21, 22, 23),
        )

    def test_mixed_ports_and_ranges(self):
        self.assertEqual(
            parse_ports("22,80,443,8000-8002"),
            (22, 80, 443, 8000, 8001, 8002),
        )

    def test_duplicate_ports_are_removed(self):
        self.assertEqual(
            parse_ports("80,80,79-81"),
            (79, 80, 81),
        )

    def test_empty_specification_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("")

    def test_port_zero_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("0")

    def test_port_above_65535_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("65536")

    def test_reverse_range_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("100-50")

    def test_non_numeric_port_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_ports("http")


if __name__ == "__main__":
    unittest.main()
