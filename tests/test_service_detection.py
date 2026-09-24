"""Tests for NightRecon service detection."""

import socket
import unittest
from unittest.mock import MagicMock, patch

from nightrecon.service_detection import (
    ServiceDetectionResult,
    detect_service,
    identify_service,
    parse_http_response,
)


class ServiceDetectionTests(unittest.TestCase):

    def test_http_response_parser_captures_response_headers(self):
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx\r\n"
            b"Content-Security-Policy: default-src 'self'\r\n"
            b"X-Content-Type-Options: nosniff\r\n"
            b"\r\n"
        )
    
        metadata = parse_http_response(response)
    
        self.assertEqual(
            metadata.headers,
            (
                ("server", "nginx"),
               (
                     "content-security-policy",
                    "default-src 'self'",
                ),
                ("x-content-type-options", "nosniff"),
            ),
        )

    def test_https_detection_includes_response_headers(self):
        fake_socket = MagicMock()
        fake_socket.recv.side_effect = socket.timeout()

        with patch(
            "nightrecon.service_detection.socket.socket",
            return_value=fake_socket,
        ):
            with patch(
                "nightrecon.service_detection.probe_tls_service"
            ) as tls_probe:
                tls_probe.return_value.tls_version = "TLSv1.3"
                tls_probe.return_value.cipher = (
                    "TLS_AES_256_GCM_SHA384"
                )
                tls_probe.return_value.certificate_subject = ""
                tls_probe.return_value.certificate_issuer = ""
                tls_probe.return_value.certificate_not_before = ""
                tls_probe.return_value.certificate_not_after = ""
                tls_probe.return_value.certificate_sans = ()
                tls_probe.return_value.certificate_sha256 = ""
                tls_probe.return_value.http_status = (
                    "HTTP/1.1 200 OK"
                )
                tls_probe.return_value.http_server = "nginx"
                tls_probe.return_value.http_headers = (
                    ("server", "nginx"),
                    (
                        "content-security-policy",
                        "default-src 'self'",
                    ),
                )

                result = detect_service(
                    address="127.0.0.1",
                    port=443,
                    timeout=1.0,
                )

        self.assertEqual(
            result.http_headers,
            (
                ("server", "nginx"),
                (
                    "content-security-policy",
                    "default-src 'self'",
                ),
            ),
        )

    def test_https_detection_includes_https_http_metadata(self):
        fake_socket = MagicMock()
        fake_socket.recv.side_effect = socket.timeout()

        with patch(
            "nightrecon.service_detection.socket.socket",
            return_value=fake_socket,
        ):
            with patch(
                "nightrecon.service_detection.probe_tls_service"
            ) as tls_probe:
                tls_probe.return_value.tls_version = "TLSv1.3"
                tls_probe.return_value.cipher = (
                    "TLS_AES_256_GCM_SHA384"
                )
                tls_probe.return_value.certificate_subject = ""
                tls_probe.return_value.certificate_issuer = ""
                tls_probe.return_value.certificate_not_before = ""
                tls_probe.return_value.certificate_not_after = ""
                tls_probe.return_value.certificate_sans = ()
                tls_probe.return_value.certificate_sha256 = ""
                tls_probe.return_value.http_status = (
                    "HTTP/1.1 200 OK"
                )
                tls_probe.return_value.http_server = "nginx"

                result = detect_service(
                    address="127.0.0.1",
                    port=443,
                    timeout=1.0,
                )

        self.assertEqual(
            result.http_status,
            "HTTP/1.1 200 OK",
        )
        self.assertEqual(
            result.http_server,
            "nginx",
        )

    def test_https_detection_includes_certificate_sha256(self):
        fake_socket = MagicMock()
        fake_socket.recv.side_effect = socket.timeout()

        with patch(
            "nightrecon.service_detection.socket.socket",
            return_value=fake_socket,
        ):
            with patch(
                "nightrecon.service_detection.probe_tls_service"
            ) as tls_probe:
                tls_probe.return_value.tls_version = "TLSv1.3"
                tls_probe.return_value.cipher = (
                    "TLS_AES_256_GCM_SHA384"
                )
                tls_probe.return_value.certificate_subject = ""
                tls_probe.return_value.certificate_issuer = ""
                tls_probe.return_value.certificate_not_before = ""
                tls_probe.return_value.certificate_not_after = ""
                tls_probe.return_value.certificate_sans = ()
                tls_probe.return_value.certificate_sha256 = (
                    "00112233445566778899aabbccddeeff"
                    "00112233445566778899aabbccddeeff"
                )

                result = detect_service(
                    address="127.0.0.1",
                    port=443,
                    timeout=1.0,
                )

        self.assertEqual(
            result.tls_certificate_sha256,
            (
                "00112233445566778899aabbccddeeff"
                "00112233445566778899aabbccddeeff"
            ),
        )

    def test_https_detection_includes_certificate_sans(self):
        fake_socket = MagicMock()
        fake_socket.recv.side_effect = socket.timeout()

        with patch(
            "nightrecon.service_detection.socket.socket",
            return_value=fake_socket,
        ):
            with patch(
                "nightrecon.service_detection.probe_tls_service"
            ) as tls_probe:
                tls_probe.return_value.tls_version = "TLSv1.3"
                tls_probe.return_value.cipher = (
                    "TLS_AES_256_GCM_SHA384"
                )
                tls_probe.return_value.certificate_subject = (
                    "CN=example.test"
                )
                tls_probe.return_value.certificate_issuer = (
                    "O=NightRecon Test CA"
                )
                tls_probe.return_value.certificate_not_before = ""
                tls_probe.return_value.certificate_not_after = ""
                tls_probe.return_value.certificate_sans = (
                    "example.test",
                    "www.example.test",
                )

                result = detect_service(
                    address="127.0.0.1",
                    port=443,
                    timeout=1.0,
                )

        self.assertEqual(
            result.tls_certificate_sans,
            (
                "example.test",
                "www.example.test",
            ),
        )

    def test_https_detection_includes_certificate_validity_dates(self):
        fake_socket = MagicMock()
        fake_socket.recv.side_effect = socket.timeout()

        with patch(
            "nightrecon.service_detection.socket.socket",
            return_value=fake_socket,
        ):
            with patch(
                "nightrecon.service_detection.probe_tls_service"
            ) as tls_probe:
                tls_probe.return_value.tls_version = "TLSv1.3"
                tls_probe.return_value.cipher = (
                    "TLS_AES_256_GCM_SHA384"
                )
                tls_probe.return_value.certificate_subject = (
                    "CN=example.test"
                )
                tls_probe.return_value.certificate_issuer = (
                    "O=NightRecon Test CA"
                )
                tls_probe.return_value.certificate_not_before = (
                    "2026-01-01T00:00:00+00:00"
                )
                tls_probe.return_value.certificate_not_after = (
                    "2027-01-01T00:00:00+00:00"
                )

                result = detect_service(
                    address="127.0.0.1",
                    port=443,
                    timeout=1.0,
                )

        self.assertEqual(
            result.tls_certificate_not_before,
            "2026-01-01T00:00:00+00:00",
        )
        self.assertEqual(
            result.tls_certificate_not_after,
            "2027-01-01T00:00:00+00:00",
        )

    def test_https_detection_forwards_server_hostname_for_sni(self):
        fake_socket = MagicMock()
        fake_socket.recv.side_effect = socket.timeout()

        with patch(
            "nightrecon.service_detection.socket.socket",
            return_value=fake_socket,
        ):
            with patch(
                "nightrecon.service_detection.probe_tls_service"
            ) as tls_probe:
                tls_probe.return_value.tls_version = "TLSv1.3"
                tls_probe.return_value.cipher = (
                    "TLS_AES_256_GCM_SHA384"
                )
                tls_probe.return_value.certificate_subject = ""
                tls_probe.return_value.certificate_issuer = ""

                detect_service(
                    address="192.0.2.10",
                    port=443,
                    timeout=1.0,
                    server_hostname="example.test",
                )

        tls_probe.assert_called_once_with(
            address="192.0.2.10",
            port=443,
            timeout=1.0,
            server_hostname="example.test",
        )

    def test_https_detection_includes_tls_metadata(self):
        fake_socket = MagicMock()
        fake_socket.recv.side_effect = socket.timeout()

        with patch(
            "nightrecon.service_detection.socket.socket",
            return_value=fake_socket,
        ):
            with patch(
                "nightrecon.service_detection.probe_tls_service"
            ) as tls_probe:
                tls_probe.return_value.tls_version = "TLSv1.3"
                tls_probe.return_value.cipher = (
                    "TLS_AES_256_GCM_SHA384"
                )
                tls_probe.return_value.certificate_subject = (
                    "commonName=example.test"
                )
                tls_probe.return_value.certificate_issuer = (
                    "organizationName=NightRecon Test CA"
                )

                result = detect_service(
                    address="127.0.0.1",
                    port=443,
                    timeout=1.0,
                )

        self.assertEqual(result.service, "https")
        self.assertEqual(result.tls_version, "TLSv1.3")
        self.assertEqual(
            result.tls_cipher,
            "TLS_AES_256_GCM_SHA384",
        )

        self.assertEqual(
            result.tls_certificate_subject,
            "commonName=example.test",
        )
        self.assertEqual(
            result.tls_certificate_issuer,
            "organizationName=NightRecon Test CA",
        )

        tls_probe.assert_called_once_with(
                address="127.0.0.1",
                port=443,
                timeout=1.0,
                server_hostname=None,
        )


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
                with patch(
                    "nightrecon.service_detection.probe_tls_service"
                ) as tls_probe:
                    tls_probe.return_value.tls_version = "TLSv1.3"
                    tls_probe.return_value.cipher = (
                        "TLS_AES_256_GCM_SHA384"
                    )
                    tls_probe.return_value.certificate_subject = ""
                    tls_probe.return_value.certificate_issuer = ""
                    tls_probe.return_value.http_status = ""
                    tls_probe.return_value.http_server = ""

                    result = detect_service(
                        address="127.0.0.1",
                        port=443,
                        timeout=1.0,
                    )

        self.assertEqual(result.service, "https")
        self.assertEqual(result.http_status, "")
        self.assertEqual(result.http_server, "")

        http_probe.assert_not_called()

        tls_probe.assert_called_once_with(
            address="127.0.0.1",
            port=443,
            timeout=1.0,
            server_hostname=None,
        )

    def test_http_detection_analyzes_security_headers(self):
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
                http_probe.return_value.server = "nginx"
                http_probe.return_value.headers = (
                    (
                        "content-security-policy",
                        "default-src 'self'",
                    ),
                    ("x-content-type-options", "nosniff"),
                    ("x-frame-options", "DENY"),
                )

                result = detect_service(
                    address="127.0.0.1",
                    port=80,
                    timeout=1.0,
                )

        self.assertEqual(
            result.security_headers_present,
            (
                "content-security-policy",
                "x-content-type-options",
                "x-frame-options",
            ),
        )
        self.assertEqual(
            result.security_headers_missing,
            (
                "strict-transport-security",
                "referrer-policy",
                "permissions-policy",
            ),
        )

    def test_http_detection_includes_response_headers(self):
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
                http_probe.return_value.server = "nginx"
                http_probe.return_value.headers = (
                    ("server", "nginx"),
                    (
                        "content-security-policy",
                        "default-src 'self'",
                    ),
                )

                result = detect_service(
                    address="127.0.0.1",
                    port=80,
                    timeout=1.0,
                )

        self.assertEqual(
            result.http_headers,
            (
                ("server", "nginx"),
                (
                    "content-security-policy",
                    "default-src 'self'",
                ),
            ),
        )

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
