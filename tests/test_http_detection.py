"""Tests for NightRecon HTTP service intelligence."""

import socket
import unittest
from unittest.mock import MagicMock, patch

from nightrecon.service_detection import (
    parse_http_response,
    probe_http_service,
)


class HttpDetectionTests(unittest.TestCase):
    def test_http_response_metadata_is_parsed(self):
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx/1.24.0\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: 12\r\n"
            b"\r\n"
            b"Hello World!"
        )

        metadata = parse_http_response(response)

        self.assertEqual(
            metadata.status_line,
            "HTTP/1.1 200 OK",
        )
        self.assertEqual(
            metadata.server,
            "nginx/1.24.0",
        )

    def test_http_response_without_server_header_is_supported(self):
        response = (
            b"HTTP/1.1 204 No Content\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )

        metadata = parse_http_response(response)

        self.assertEqual(
            metadata.status_line,
            "HTTP/1.1 204 No Content",
        )
        self.assertEqual(metadata.server, "")

    def test_http_probe_timeout_returns_empty_metadata(self):
        fake_socket = MagicMock()
        fake_socket.recv.side_effect = socket.timeout()

        with patch(
            "nightrecon.service_detection.socket.socket",
            return_value=fake_socket,
        ):
            metadata = probe_http_service(
                address="127.0.0.1",
                port=80,
                timeout=1.0,
            )

        self.assertEqual(metadata.status_line, "")
        self.assertEqual(metadata.server, "")
        fake_socket.close.assert_called_once()

    def test_http_probe_connection_error_returns_empty_metadata(self):
        fake_socket = MagicMock()
        fake_socket.connect.side_effect = OSError(
            10061,
            "Connection refused",
        )

        with patch(
            "nightrecon.service_detection.socket.socket",
            return_value=fake_socket,
        ):
            result = probe_http_service(
                address="127.0.0.1",
                port=80,
                timeout=1.0,
            )

        self.assertEqual(result.status_line, "")
        self.assertEqual(result.server, "")
        fake_socket.close.assert_called_once()

    def test_http_probe_sends_bounded_head_request(self):
        fake_socket = MagicMock()
        fake_socket.recv.return_value = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx\r\n"
            b"\r\n"
        )

        with patch(
            "nightrecon.service_detection.socket.socket",
            return_value=fake_socket,
        ):
            metadata = probe_http_service(
                address="127.0.0.1",
                port=80,
                timeout=2.0,
            )

        fake_socket.settimeout.assert_called_once_with(2.0)
        fake_socket.connect.assert_called_once_with(
            ("127.0.0.1", 80)
        )

        fake_socket.sendall.assert_called_once_with(
            b"HEAD / HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )

        fake_socket.recv.assert_called_once_with(4096)
        fake_socket.close.assert_called_once()

        self.assertEqual(
            metadata.status_line,
            "HTTP/1.1 200 OK",
        )
        self.assertEqual(metadata.server, "nginx")


if __name__ == "__main__":
    unittest.main()