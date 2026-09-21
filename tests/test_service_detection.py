"""Tests for NightRecon service detection."""

import socket
import unittest
from unittest.mock import MagicMock, patch

from nightrecon.service_detection import (
    ServiceDetectionResult,
    detect_service,
    identify_service,
)


class ServiceDetectionTests(unittest.TestCase):

    def test_https_service_does_not_use_plain_http_probe(self):
        fake_socket = MagicMock()
        fake_socket.recv.side_effect = socket.timeout()

        with patch(
            "nightrecon.service_detection.socket.socket",
            return_value=fake_socket,
     ):
            with patch(
                "nightrecon.service_detection.probe_http_service"
            ) as http_probe:
                result = detect_service(
                    address="127.0.0.1",
                    port=443,
                    timeout=1.0,
                )

        self.assertEqual(result.service, "https")
        self.assertEqual(result.http_status, "")
        self.assertEqual(result.http_server, "")

        http_probe.assert_not_called()
    def test_http_detection_includes_http_metadata(self):
        fake_socket = MagicMock()
        fake_socket.recv.side_effect = socket.timeout()

        with patch(
            "nightrecon.service_detection.socket.socket",
            return_value=fake_socket,
        ):
            with patch(
                "nightrecon.service_detection.probe_http_service"
            ) as http_probe:
                http_probe.return_value.status_line = "HTTP/1.1 200 OK"
                http_probe.return_value.server = "nginx/1.24.0"

                result = detect_service(
                    address="127.0.0.1",
                    port=80,
                    timeout=1.0,
                )

        self.assertEqual(result.service, "http")
        self.assertEqual(result.http_status, "HTTP/1.1 200 OK")
        self.assertEqual(result.http_server, "nginx/1.24.0")

        http_probe.assert_called_once_with(
            address="127.0.0.1",
            port=80,
            timeout=1.0,
        )

    def test_service_detection_result_stores_observation(self):
        result = ServiceDetectionResult(
            address="127.0.0.1",
            port=22,
            service="ssh",
            banner="SSH-2.0-OpenSSH",
        )

        self.assertEqual(result.address, "127.0.0.1")
        self.assertEqual(result.port, 22)
        self.assertEqual(result.service, "ssh")
        self.assertEqual(result.banner, "SSH-2.0-OpenSSH")

    def test_common_service_is_identified_by_port(self):
        self.assertEqual(identify_service(22), "ssh")
        self.assertEqual(identify_service(80), "http")
        self.assertEqual(identify_service(443), "https")

    def test_unknown_service_returns_unknown(self):
        self.assertEqual(identify_service(65000), "unknown")

    def test_detect_service_reads_passive_banner(self):
        fake_socket = MagicMock()
        fake_socket.recv.return_value = b"SSH-2.0-OpenSSH_9.6\r\n"

        with patch(
            "nightrecon.service_detection.socket.socket",
            return_value=fake_socket,
        ) as socket_factory:
            result = detect_service(
                address="127.0.0.1",
                port=22,
                timeout=2.0,
            )

        self.assertEqual(result.address, "127.0.0.1")
        self.assertEqual(result.port, 22)
        self.assertEqual(result.service, "ssh")
        self.assertEqual(result.banner, "SSH-2.0-OpenSSH_9.6")

        socket_factory.assert_called_once_with(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )
        fake_socket.settimeout.assert_called_once_with(2.0)
        fake_socket.connect.assert_called_once_with(
            ("127.0.0.1", 22)
        )
        fake_socket.recv.assert_called_once_with(1024)
        fake_socket.close.assert_called_once()

    def test_detect_service_connection_error_is_reported(self):
        fake_socket = MagicMock()
        fake_socket.connect.side_effect = OSError(
            10061,
            "Connection refused",
        )

        with patch(
            "nightrecon.service_detection.socket.socket",
            return_value=fake_socket,
        ):
            result = detect_service(
                address="127.0.0.1",
                port=22,
                timeout=1.0,
            )

        self.assertEqual(result.address, "127.0.0.1")
        self.assertEqual(result.port, 22)
        self.assertEqual(result.service, "ssh")
        self.assertEqual(result.banner, "")
        self.assertEqual(result.error_code, 10061)
        fake_socket.close.assert_called_once()

    def test_detect_service_timeout_returns_empty_banner(self):
        fake_socket = MagicMock()
        fake_socket.recv.side_effect = socket.timeout()

        with patch(
             "nightrecon.service_detection.socket.socket",
            return_value=fake_socket,
        ):
            with patch(
                "nightrecon.service_detection.probe_http_service"
        ) as http_probe:
                http_probe.return_value.status_line = ""
                http_probe.return_value.server = ""

                result = detect_service(
                    address="127.0.0.1",
                    port=80,
                    timeout=1.0,
                )

            self.assertEqual(result.address, "127.0.0.1")
            self.assertEqual(result.port, 80)
            self.assertEqual(result.service, "http")
            self.assertEqual(result.banner, "")
            self.assertEqual(result.http_status, "")
            self.assertEqual(result.http_server, "")

        http_probe.assert_called_once_with(
            address="127.0.0.1",
            port=80,
            timeout=1.0
        )

        fake_socket.close.assert_called_once()

    def test_banner_fingerprint_overrides_unknown_port(self):
        fake_socket = MagicMock()
        fake_socket.recv.return_value = b"SSH-2.0-OpenSSH_9.6\r\n"

        with patch(
            "nightrecon.service_detection.socket.socket",
            return_value=fake_socket,
        ):
            result = detect_service(
                address="127.0.0.1",
                port=2222,
                timeout=1.0,
            )

        self.assertEqual(result.port, 2222)
        self.assertEqual(result.service, "ssh")
        self.assertEqual(result.banner, "SSH-2.0-OpenSSH_9.6")


if __name__ == "__main__":
    unittest.main()