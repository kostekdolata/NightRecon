"""Tests for bounded NightRecon host discovery."""

import errno
import socket
import unittest
from unittest.mock import MagicMock, patch

from nightrecon.host_discovery import (
    HostDiscoveryResult,
    discover_hosts,
    probe_host,
)


class HostDiscoveryTests(unittest.TestCase):
    def test_open_tcp_port_marks_host_responsive(self):
        fake_socket = MagicMock()
        fake_socket.connect_ex.return_value = 0

        with patch(
            "nightrecon.host_discovery.socket.socket",
            return_value=fake_socket,
        ):
            result = probe_host(
                address="192.0.2.10",
                ports=(443,),
                timeout=0.5,
            )

        self.assertEqual(
            result,
            HostDiscoveryResult(
                address="192.0.2.10",
                responsive=True,
                method="tcp-connect",
                port=443,
                observation="tcp-open",
                error_code=0,
            ),
        )
        fake_socket.settimeout.assert_called_once_with(0.5)

    def test_refused_tcp_port_still_marks_host_responsive(self):
        fake_socket = MagicMock()
        fake_socket.connect_ex.return_value = errno.ECONNREFUSED

        with patch(
            "nightrecon.host_discovery.socket.socket",
            return_value=fake_socket,
        ):
            result = probe_host(
                address="192.0.2.10",
                ports=(22,),
                timeout=0.5,
            )

        self.assertTrue(result.responsive)
        self.assertEqual(result.observation, "tcp-refused")
        self.assertEqual(result.port, 22)

    def test_unreachable_ports_return_no_response(self):
        fake_socket = MagicMock()
        fake_socket.connect_ex.return_value = errno.EHOSTUNREACH

        with patch(
            "nightrecon.host_discovery.socket.socket",
            return_value=fake_socket,
        ):
            result = probe_host(
                address="192.0.2.10",
                ports=(22, 443),
                timeout=0.5,
            )

        self.assertFalse(result.responsive)
        self.assertEqual(result.observation, "no-response")
        self.assertIsNone(result.port)
        self.assertEqual(result.error_code, errno.EHOSTUNREACH)

    def test_discovery_returns_deterministic_address_order(self):
        def fake_probe(address, ports, timeout):
            return HostDiscoveryResult(
                address=address,
                responsive=address.endswith(".2"),
                method="tcp-connect",
                port=443 if address.endswith(".2") else None,
                observation=(
                    "tcp-open"
                    if address.endswith(".2")
                    else "no-response"
                ),
                error_code=0 if address.endswith(".2") else None,
            )

        with patch(
            "nightrecon.host_discovery.probe_host",
            side_effect=fake_probe,
        ):
            result = discover_hosts(
                cidr="192.0.2.0/30",
                ports=(443,),
                timeout=0.5,
                max_workers=2,
                max_hosts=8,
            )

        self.assertEqual(
            tuple(item.address for item in result),
            ("192.0.2.1", "192.0.2.2"),
        )
        self.assertEqual(
            tuple(item.address for item in result if item.responsive),
            ("192.0.2.2",),
        )

    def test_host_limit_is_enforced_before_probing(self):
        with patch(
            "nightrecon.host_discovery.probe_host"
        ) as probe:
            with self.assertRaisesRegex(
                ValueError,
                "exceeds max_hosts",
            ):
                discover_hosts(
                    cidr="10.0.0.0/24",
                    ports=(443,),
                    timeout=0.5,
                    max_workers=10,
                    max_hosts=16,
                )

        probe.assert_not_called()

    def test_invalid_timeout_workers_ports_and_limit_are_rejected(self):
        with self.assertRaises(ValueError):
            discover_hosts(
                cidr="192.0.2.0/30",
                ports=(443,),
                timeout=0,
            )

        with self.assertRaises(ValueError):
            discover_hosts(
                cidr="192.0.2.0/30",
                ports=(443,),
                max_workers=0,
            )

        with self.assertRaises(ValueError):
            discover_hosts(
                cidr="192.0.2.0/30",
                ports=(),
            )

        with self.assertRaises(ValueError):
            discover_hosts(
                cidr="192.0.2.0/30",
                ports=(70000,),
            )

        with self.assertRaises(ValueError):
            discover_hosts(
                cidr="192.0.2.0/30",
                ports=(443,),
                max_hosts=0,
            )

    def test_ipv6_uses_ipv6_socket_family(self):
        fake_socket = MagicMock()
        fake_socket.connect_ex.return_value = 0

        with patch(
            "nightrecon.host_discovery.socket.socket",
            return_value=fake_socket,
        ) as socket_factory:
            result = probe_host(
                address="2001:db8::1",
                ports=(443,),
                timeout=0.5,
            )

        self.assertTrue(result.responsive)
        socket_factory.assert_called_once_with(
            socket.AF_INET6,
            socket.SOCK_STREAM,
        )


if __name__ == "__main__":
    unittest.main()
