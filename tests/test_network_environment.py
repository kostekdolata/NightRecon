"""Tests for local network route/interface awareness."""

import unittest

from nightrecon_red_engine.network_environment import (
    parse_linux_ip_route,
    parse_windows_route_print,
)


class NetworkEnvironmentTests(unittest.TestCase):
    def test_linux_routes_parse_ipv4_default_and_specific(self):
        routes = parse_linux_ip_route(
            """default via 192.0.2.1 dev eth0 metric 100
192.0.2.0/24 dev eth0 metric 100
"""
        )
        self.assertEqual(len(routes), 2)
        self.assertEqual(routes[0].destination, "0.0.0.0/0")
        self.assertEqual(routes[0].gateway, "192.0.2.1")
        self.assertEqual(routes[0].interface, "eth0")
        self.assertEqual(routes[0].metric, 100)

    def test_linux_routes_parse_ipv6(self):
        routes = parse_linux_ip_route(
            "default via 2001:db8::1 dev eth0 metric 20",
            family="ipv6",
        )
        self.assertEqual(routes[0].destination, "::/0")
        self.assertEqual(routes[0].family, "ipv6")

    def test_windows_route_print_parses_active_route(self):
        routes = parse_windows_route_print(
            """          0.0.0.0          0.0.0.0      192.0.2.1     192.0.2.20     25
        192.0.2.0    255.255.255.0         On-link     192.0.2.20    281
"""
        )
        self.assertEqual(len(routes), 2)
        self.assertEqual(routes[0].destination, "0.0.0.0/0")
        self.assertEqual(routes[0].metric, 25)


if __name__ == "__main__":
    unittest.main()
