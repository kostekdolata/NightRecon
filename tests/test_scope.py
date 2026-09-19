"""Tests for NightRecon scope authorization."""

import unittest

from nightrecon.scope import Scope
from nightrecon.targets import parse_target


class ScopeTests(unittest.TestCase):
    def test_exact_ipv4_is_authorized(self):
        scope = Scope.from_values(["127.0.0.1"])
        self.assertTrue(scope.is_authorized(parse_target("127.0.0.1")))

    def test_different_ipv4_is_rejected(self):
        scope = Scope.from_values(["127.0.0.1"])
        self.assertFalse(scope.is_authorized(parse_target("127.0.0.2")))

    def test_ip_inside_cidr_is_authorized(self):
        scope = Scope.from_values(["192.168.1.0/24"])
        self.assertTrue(scope.is_authorized(parse_target("192.168.1.25")))

    def test_ip_outside_cidr_is_rejected(self):
        scope = Scope.from_values(["192.168.1.0/24"])
        self.assertFalse(scope.is_authorized(parse_target("192.168.2.25")))

    def test_subnet_inside_cidr_is_authorized(self):
        scope = Scope.from_values(["10.0.0.0/8"])
        self.assertTrue(scope.is_authorized(parse_target("10.10.0.0/16")))

    def test_larger_network_is_rejected(self):
        scope = Scope.from_values(["10.10.0.0/16"])
        self.assertFalse(scope.is_authorized(parse_target("10.0.0.0/8")))

    def test_exact_hostname_is_authorized(self):
        scope = Scope.from_values(["example.com"])
        self.assertTrue(scope.is_authorized(parse_target("example.com")))

    def test_different_hostname_is_rejected(self):
        scope = Scope.from_values(["example.com"])
        self.assertFalse(scope.is_authorized(parse_target("api.example.com")))

    def test_empty_scope_is_rejected(self):
        with self.assertRaises(ValueError):
            Scope.from_values([])


if __name__ == "__main__":
    unittest.main()
