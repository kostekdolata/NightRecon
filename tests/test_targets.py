"""Tests for NightRecon target parsing."""

import unittest

from nightrecon.targets import TargetType, parse_target


class TargetParsingTests(unittest.TestCase):
    def test_ipv4_target(self):
        target = parse_target("127.0.0.1")
        self.assertEqual(target.value, "127.0.0.1")
        self.assertEqual(target.target_type, TargetType.IPV4)

    def test_ipv6_target(self):
        target = parse_target("::1")
        self.assertEqual(target.value, "::1")
        self.assertEqual(target.target_type, TargetType.IPV6)

    def test_cidr_target(self):
        target = parse_target("192.168.1.0/24")
        self.assertEqual(target.value, "192.168.1.0/24")
        self.assertEqual(target.target_type, TargetType.CIDR)

    def test_hostname_target(self):
        target = parse_target("Example.COM")
        self.assertEqual(target.value, "example.com")
        self.assertEqual(target.target_type, TargetType.HOSTNAME)

    def test_invalid_target(self):
        with self.assertRaises(ValueError):
            parse_target("not a valid target")

    def test_empty_target(self):
        with self.assertRaises(ValueError):
            parse_target("   ")

    def test_invalid_cidr(self):
        with self.assertRaises(ValueError):
            parse_target("192.168.1.0/999")


if __name__ == "__main__":
    unittest.main()
