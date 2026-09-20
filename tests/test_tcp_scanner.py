"""Tests for the NightRecon TCP scanner."""

import socket
import unittest
from unittest.mock import MagicMock, patch

from nightrecon.tcp_scanner import (
    TcpPortResult,
    scan_tcp_port,
    scan_tcp_ports,
)


class TcpScannerTests(unittest.TestCase):
    def test_open_ipv4_port(self):
        fake_socket = MagicMock()
        fake_socket.connect_ex.return_value = 0

        with patch(
            "nightrecon.tcp_scanner.socket.socket",
            return_value=fake_socket,
        ) as socket_factory:
            result = scan_tcp_port(
                "127.0.0.1",
                443,
                2.0,
            )

        self.assertTrue(result.is_open)
        self.assertEqual(result.address, "127.0.0.1")
        self.assertEqual(result.port, 443)
        self.assertEqual(result.error_code, 0)

        socket_factory.assert_called_once_with(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )
        fake_socket.settimeout.assert_called_once_with(2.0)
        fake_socket.connect_ex.assert_called_once_with(
            ("127.0.0.1", 443)
        )
        fake_socket.close.assert_called_once()

    def test_closed_ipv4_port(self):
        fake_socket = MagicMock()
        fake_socket.connect_ex.return_value = 10061

        with patch(
            "nightrecon.tcp_scanner.socket.socket",
            return_value=fake_socket,
        ):
            result = scan_tcp_port(
                "127.0.0.1",
                80,
                2.0,
            )

        self.assertFalse(result.is_open)
        self.assertEqual(result.error_code, 10061)
        fake_socket.close.assert_called_once()

    def test_ipv6_uses_ipv6_socket(self):
        fake_socket = MagicMock()
        fake_socket.connect_ex.return_value = 0

        with patch(
            "nightrecon.tcp_scanner.socket.socket",
            return_value=fake_socket,
        ) as socket_factory:
            result = scan_tcp_port(
                "::1",
                443,
                1.0,
            )

        self.assertTrue(result.is_open)

        socket_factory.assert_called_once_with(
            socket.AF_INET6,
            socket.SOCK_STREAM,
        )

        fake_socket.connect_ex.assert_called_once_with(
            ("::1", 443, 0, 0)
        )

    def test_multiple_ports_are_scanned_and_sorted(self):
        def fake_scan(address, port, timeout):
            return TcpPortResult(
                address=address,
                port=port,
                is_open=port == 443,
                error_code=0 if port == 443 else 1,
            )

        with patch(
            "nightrecon.tcp_scanner.scan_tcp_port",
            side_effect=fake_scan,
        ) as scan_port:
            results = scan_tcp_ports(
                "127.0.0.1",
                (443, 22, 80),
                2.0,
                max_workers=3,
            )

        self.assertEqual(
            tuple(result.port for result in results),
            (22, 80, 443),
        )
        self.assertEqual(scan_port.call_count, 3)

    def test_open_port_state_is_preserved(self):
        def fake_scan(address, port, timeout):
            return TcpPortResult(
                address=address,
                port=port,
                is_open=port == 80,
                error_code=0 if port == 80 else 10061,
            )

        with patch(
            "nightrecon.tcp_scanner.scan_tcp_port",
            side_effect=fake_scan,
        ):
            results = scan_tcp_ports(
                "127.0.0.1",
                (22, 80),
                2.0,
                max_workers=2,
            )

        self.assertFalse(results[0].is_open)
        self.assertTrue(results[1].is_open)

    def test_invalid_ip_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_tcp_port(
                "not-an-ip",
                443,
                2.0,
            )

    def test_port_zero_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_tcp_port(
                "127.0.0.1",
                0,
                2.0,
            )

    def test_port_above_65535_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_tcp_port(
                "127.0.0.1",
                65536,
                2.0,
            )

    def test_invalid_timeout_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_tcp_port(
                "127.0.0.1",
                443,
                0,
            )

    def test_empty_port_collection_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_tcp_ports(
                "127.0.0.1",
                (),
                2.0,
            )

    def test_invalid_worker_count_is_rejected(self):
        with self.assertRaises(ValueError):
            scan_tcp_ports(
                "127.0.0.1",
                (80,),
                2.0,
                max_workers=0,
            )


if __name__ == "__main__":
    unittest.main()
