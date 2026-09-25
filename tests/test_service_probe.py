"""Tests for bounded active service probes."""

import socket
import unittest
from unittest.mock import MagicMock, patch

from nightrecon.service_fingerprint import ServiceFingerprint
from nightrecon.service_probe import (
    match_service_probe_response,
    probe_tcp_service,
    select_service_probes,
)


class ServiceProbeEngineTests(unittest.TestCase):
    def test_low_intensity_selects_common_fallback_probe(self):
        probes = select_service_probes(
            port=9000,
            intensity=1,
        )

        self.assertEqual(
            tuple(probe.probe_id for probe in probes),
            ("http-head",),
        )

    def test_port_specific_probe_is_selected_above_intensity(self):
        probes = select_service_probes(
            port=6379,
            intensity=1,
        )

        self.assertIn(
            "redis-ping",
            tuple(probe.probe_id for probe in probes),
        )

    def test_raw_print_port_is_excluded_from_active_probes(self):
        self.assertEqual(
            select_service_probes(
                port=9100,
                intensity=9,
            ),
            (),
        )

    def test_http_probe_matches_server_product_and_version(self):
        result = match_service_probe_response(
            "http-head",
            (
                b"HTTP/1.1 200 OK\r\n"
                b"Server: nginx/1.24.0\r\n"
                b"Content-Length: 0\r\n\r\n"
            ),
        )

        self.assertEqual(
            result,
            ServiceFingerprint(
                protocol="http",
                product="nginx",
                version="1.24.0",
                source="active-probe:http-head",
                evidence="Server: nginx/1.24.0",
                confidence="high",
            ),
        )

    def test_redis_probe_matches_pong_without_guessing_version(self):
        result = match_service_probe_response(
            "redis-ping",
            b"+PONG\r\n",
        )

        self.assertEqual(
            result,
            ServiceFingerprint(
                protocol="redis",
                product="Redis",
                source="active-probe:redis-ping",
                evidence="+PONG",
                confidence="high",
            ),
        )

    def test_memcached_probe_extracts_version(self):
        result = match_service_probe_response(
            "memcached-version",
            b"VERSION 1.6.22\r\n",
        )

        self.assertEqual(
            result,
            ServiceFingerprint(
                protocol="memcached",
                product="memcached",
                version="1.6.22",
                source="active-probe:memcached-version",
                evidence="VERSION 1.6.22",
                confidence="high",
            ),
        )

    def test_unknown_probe_response_does_not_guess(self):
        self.assertIsNone(
            match_service_probe_response(
                "http-head",
                b"welcome\r\n",
            )
        )

    def test_probe_tcp_service_returns_first_matching_fingerprint(self):
        fake_socket = MagicMock()
        fake_socket.recv.return_value = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx/1.24.0\r\n\r\n"
        )

        with patch(
            "nightrecon.service_probe.socket.create_connection",
            return_value=fake_socket,
        ) as create_connection:
            result = probe_tcp_service(
                address="127.0.0.1",
                port=9000,
                timeout=1.0,
                intensity=1,
            )

        self.assertEqual(result.protocol, "http")
        self.assertEqual(result.product, "nginx")
        fake_socket.sendall.assert_called_once()
        fake_socket.recv.assert_called_once_with(4096)
        fake_socket.close.assert_called_once()
        create_connection.assert_called_once_with(
            ("127.0.0.1", 9000),
            timeout=1.0,
        )

    def test_probe_tcp_service_is_fail_soft_and_tries_next_probe(self):
        first_socket = MagicMock()
        first_socket.recv.side_effect = socket.timeout()

        second_socket = MagicMock()
        second_socket.recv.return_value = b"+PONG\r\n"

        with patch(
            "nightrecon.service_probe.socket.create_connection",
            side_effect=(
                first_socket,
                second_socket,
            ),
        ):
            result = probe_tcp_service(
                address="127.0.0.1",
                port=6379,
                timeout=1.0,
                intensity=1,
            )

        self.assertEqual(result.protocol, "redis")
        first_socket.close.assert_called_once()
        second_socket.close.assert_called_once()

    def test_probe_tcp_service_skips_excluded_port_without_connecting(self):
        with patch(
            "nightrecon.service_probe.socket.create_connection"
        ) as create_connection:
            result = probe_tcp_service(
                address="127.0.0.1",
                port=9100,
                timeout=1.0,
                intensity=9,
            )

        self.assertIsNone(result)
        create_connection.assert_not_called()

    def test_invalid_probe_intensity_is_rejected(self):
        with self.assertRaisesRegex(
            ValueError,
            "intensity must be between 0 and 9",
        ):
            select_service_probes(
                port=80,
                intensity=10,
            )


if __name__ == "__main__":
    unittest.main()
