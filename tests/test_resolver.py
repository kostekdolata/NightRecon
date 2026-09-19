"""Tests for NightRecon target resolution."""

import socket
import unittest
from unittest.mock import patch

from nightrecon.resolver import resolve_target
from nightrecon.targets import parse_target


class ResolverTests(unittest.TestCase):
    def test_ipv4_is_returned_without_dns_lookup(self):
        target = parse_target("127.0.0.1")

        with patch("nightrecon.resolver.socket.getaddrinfo") as getaddrinfo:
            result = resolve_target(target)

        self.assertEqual(result.target, "127.0.0.1")
        self.assertEqual(result.addresses, ("127.0.0.1",))
        getaddrinfo.assert_not_called()

    def test_ipv6_is_returned_without_dns_lookup(self):
        target = parse_target("::1")

        with patch("nightrecon.resolver.socket.getaddrinfo") as getaddrinfo:
            result = resolve_target(target)

        self.assertEqual(result.addresses, ("::1",))
        getaddrinfo.assert_not_called()

    def test_hostname_resolution(self):
        target = parse_target("example.com")

        fake_records = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("93.184.216.34", 0),
            ),
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                6,
                "",
                ("2606:2800:220:1:248:1893:25c8:1946", 0, 0, 0),
            ),
        ]

        with patch(
            "nightrecon.resolver.socket.getaddrinfo",
            return_value=fake_records,
        ):
            result = resolve_target(target)

        self.assertEqual(result.target, "example.com")
        self.assertEqual(
            result.addresses,
            (
                "2606:2800:220:1:248:1893:25c8:1946",
                "93.184.216.34",
            ),
        )

    def test_duplicate_addresses_are_removed(self):
        target = parse_target("example.com")

        fake_records = [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("93.184.216.34", 0),
            ),
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("93.184.216.34", 0),
            ),
        ]

        with patch(
            "nightrecon.resolver.socket.getaddrinfo",
            return_value=fake_records,
        ):
            result = resolve_target(target)

        self.assertEqual(
            result.addresses,
            ("93.184.216.34",),
        )

    def test_resolution_failure_is_reported(self):
        target = parse_target("example.com")

        with patch(
            "nightrecon.resolver.socket.getaddrinfo",
            side_effect=socket.gaierror,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "Unable to resolve target",
            ):
                resolve_target(target)

    def test_cidr_resolution_is_rejected(self):
        target = parse_target("192.168.1.0/24")

        with self.assertRaisesRegex(
            ValueError,
            "CIDR targets cannot be resolved",
        ):
            resolve_target(target)


if __name__ == "__main__":
    unittest.main()
