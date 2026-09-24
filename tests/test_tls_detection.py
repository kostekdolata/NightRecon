"""Tests for NightRecon TLS intelligence."""

import ssl
import unittest
from unittest.mock import MagicMock, patch
from cryptography.x509.oid import ExtensionOID
from cryptography import x509
from nightrecon.tls_detection import (
    TlsMetadata,
    format_certificate_name,
    probe_tls_service,
)
from cryptography.hazmat.primitives import hashes


class TlsDetectionTests(unittest.TestCase):

    def test_tls_probe_captures_https_http_metadata(self):
        raw_socket = MagicMock()
        tls_socket = MagicMock()

        tls_socket.version.return_value = "TLSv1.3"
        tls_socket.cipher.return_value = (
            "TLS_AES_256_GCM_SHA384",
            "TLSv1.3",
            256,
        )
        tls_socket.getpeercert.return_value = b""
        tls_socket.recv.return_value = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )

        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = (
           tls_socket
       )

        with patch(
             "nightrecon.tls_detection.socket.create_connection",
            return_value=raw_socket,
        ):
            with patch(
                "nightrecon.tls_detection.ssl.create_default_context",
                return_value=context,
            ):
                result = probe_tls_service(
                    address="127.0.0.1",
                    port=443,
                    timeout=1.0,
                    server_hostname="example.test",
                )

        self.assertEqual(
            result.http_status,
            "HTTP/1.1 200 OK",
        )
        self.assertEqual(
            result.http_server,
            "nginx",
        )

    def test_tls_probe_captures_https_response_headers(self):
        raw_socket = MagicMock()
        tls_socket = MagicMock()

        tls_socket.version.return_value = "TLSv1.3"
        tls_socket.cipher.return_value = (
            "TLS_AES_256_GCM_SHA384",
            "TLSv1.3",
            256,
        )
        tls_socket.getpeercert.return_value = b""
        tls_socket.recv.return_value = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx\r\n"
            b"Content-Security-Policy: default-src 'self'\r\n"
            b"X-Content-Type-Options: nosniff\r\n"
            b"\r\n"
        )

        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = (
            tls_socket
        )

        with patch(
            "nightrecon.tls_detection.socket.create_connection",
            return_value=raw_socket,
        ):
            with patch(
                "nightrecon.tls_detection.ssl.create_default_context",
                return_value=context,
            ):
                result = probe_tls_service(
                    address="127.0.0.1",
                    port=443,
                    timeout=1.0,
                    server_hostname="example.test",
                )

        self.assertEqual(
            result.http_headers,
            (
                ("server", "nginx"),
                (
                    "content-security-policy",
                    "default-src 'self'",
                ),
                ("x-content-type-options", "nosniff"),
            ),
        )

    def test_tls_probe_captures_certificate_sha256_fingerprint(self):
        raw_socket = MagicMock()
        tls_socket = MagicMock()

        tls_socket.version.return_value = "TLSv1.3"
        tls_socket.cipher.return_value = (
            "TLS_AES_256_GCM_SHA384",
            "TLSv1.3",
            256,
        )
        tls_socket.getpeercert.return_value = (
            b"fake-der-certificate"
        )

        certificate = MagicMock()
        certificate.subject.rfc4514_string.return_value = ""
        certificate.issuer.rfc4514_string.return_value = ""
        certificate.not_valid_before_utc.isoformat.return_value = ""
        certificate.not_valid_after_utc.isoformat.return_value = ""
        certificate.extensions.get_extension_for_class.side_effect = (
            x509.ExtensionNotFound(
        "Subject Alternative Name not found.",
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
    )
)
        certificate.fingerprint.return_value = bytes.fromhex(
            "00112233445566778899aabbccddeeff"
            "00112233445566778899aabbccddeeff"
        )

        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = (
            tls_socket
        )

        with patch(
            "nightrecon.tls_detection.socket.create_connection",
            return_value=raw_socket,
        ):
            with patch(
                "nightrecon.tls_detection.ssl.create_default_context",
                return_value=context,
            ):
                with patch(
                    "nightrecon.tls_detection.x509.load_der_x509_certificate",
                    return_value=certificate,
                ):
                    result = probe_tls_service(
                        address="127.0.0.1",
                        port=443,
                        timeout=1.0,
                    )

        self.assertEqual(
            result.certificate_sha256,
            (
                "00112233445566778899aabbccddeeff"
                "00112233445566778899aabbccddeeff"
            ),
        )

    def test_tls_probe_captures_certificate_dns_sans(self):
        raw_socket = MagicMock()
        tls_socket = MagicMock()

        tls_socket.version.return_value = "TLSv1.3"
        tls_socket.cipher.return_value = (
            "TLS_AES_256_GCM_SHA384",
            "TLSv1.3",
            256,
        )
        tls_socket.getpeercert.return_value = (
            b"fake-der-certificate"
        )

        certificate = MagicMock()
        certificate.subject.rfc4514_string.return_value = ""
        certificate.issuer.rfc4514_string.return_value = ""
        certificate.not_valid_before_utc.isoformat.return_value = ""
        certificate.not_valid_after_utc.isoformat.return_value = ""

        san_extension = MagicMock()
        certificate.extensions.get_extension_for_class.return_value = (
            san_extension
        )
        san_extension.value.get_values_for_type.return_value = [
            "example.test",
            "www.example.test",
        ]

        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = (
            tls_socket
        )

        with patch(
            "nightrecon.tls_detection.socket.create_connection",
            return_value=raw_socket,
        ):
            with patch(
                "nightrecon.tls_detection.ssl.create_default_context",
                return_value=context,
            ):
                with patch(
                    "nightrecon.tls_detection.x509.load_der_x509_certificate",
                    return_value=certificate,
                ):
                    result = probe_tls_service(
                        address="127.0.0.1",
                        port=443,
                        timeout=1.0,
                    )

        self.assertEqual(
            result.certificate_sans,
            (
                "example.test",
                "www.example.test",
            ),
        )

    def test_tls_probe_captures_certificate_validity_dates(self):
        raw_socket = MagicMock()
        tls_socket = MagicMock()

        tls_socket.version.return_value = "TLSv1.3"
        tls_socket.cipher.return_value = (
            "TLS_AES_256_GCM_SHA384",
            "TLSv1.3",
            256,
        )
        tls_socket.getpeercert.return_value = (
            b"fake-der-certificate"
        )

        certificate = MagicMock()
        certificate.subject.rfc4514_string.return_value = ""
        certificate.issuer.rfc4514_string.return_value = ""

        certificate.not_valid_before_utc.isoformat.return_value = (
            "2026-01-01T00:00:00+00:00"
        )
        certificate.not_valid_after_utc.isoformat.return_value = (
            "2027-01-01T00:00:00+00:00"
        )

        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = (
            tls_socket
        )

        with patch(
            "nightrecon.tls_detection.socket.create_connection",
            return_value=raw_socket,
        ):
            with patch(
                "nightrecon.tls_detection.ssl.create_default_context",
                return_value=context,
             ):
                with patch(
                    "nightrecon.tls_detection.x509.load_der_x509_certificate",
                    return_value=certificate,
                ):
                    result = probe_tls_service(
                        address="127.0.0.1",
                        port=443,
                       timeout=1.0,
                    )

        self.assertEqual(
            result.certificate_not_before,
            "2026-01-01T00:00:00+00:00",
        )
        self.assertEqual(
            result.certificate_not_after,
            "2027-01-01T00:00:00+00:00",
        )

    def test_tls_probe_reads_certificate_in_binary_form(self):
            raw_socket = MagicMock()
            tls_socket = MagicMock()

            tls_socket.version.return_value = "TLSv1.3"
            tls_socket.cipher.return_value = (
                "TLS_AES_256_GCM_SHA384",
                "TLSv1.3",
                256,
            )
            tls_socket.getpeercert.return_value = b"fake-der-certificate"

            certificate = MagicMock()
            certificate.subject.rfc4514_string.return_value = (
                "CN=example.test"
            )
            certificate.issuer.rfc4514_string.return_value = (
                "O=NightRecon Test CA"
            )

            context = MagicMock()
            context.wrap_socket.return_value.__enter__.return_value = (
                tls_socket
            )

            with patch(
                "nightrecon.tls_detection.socket.create_connection",
                return_value=raw_socket,
            ):
                with patch(
                    "nightrecon.tls_detection.ssl.create_default_context",
                    return_value=context,
                ):
                    with patch(
                        "cryptography.x509.load_der_x509_certificate",
                        return_value=certificate,
                    ) as load_certificate:
                        result = probe_tls_service(
                            address="127.0.0.1",
                            port=443,
                            timeout=1.0,
                        )

            tls_socket.getpeercert.assert_called_once_with(
                binary_form=True,
            )
            load_certificate.assert_called_once_with(
                b"fake-der-certificate",
            )

            self.assertEqual(
                result.certificate_subject,
                "CN=example.test",
        )
            self.assertEqual(
                result.certificate_issuer,
                "O=NightRecon Test CA",
            )

    def test_tls_probe_uses_explicit_server_hostname_for_sni(self):
        raw_socket = MagicMock()
        tls_socket = MagicMock()

        tls_socket.version.return_value = "TLSv1.3"
        tls_socket.cipher.return_value = (
            "TLS_AES_256_GCM_SHA384",
            "TLSv1.3",
            256,
        )
        tls_socket.getpeercert.return_value = {}

        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = (
            tls_socket
        )

        with patch(
            "nightrecon.tls_detection.socket.create_connection",
            return_value=raw_socket,
        ):
            with patch(
                "nightrecon.tls_detection.ssl.create_default_context",
                return_value=context,
            ):
                probe_tls_service(
                    address="192.0.2.10",
                    port=443,
                    timeout=1.0,
                    server_hostname="example.test",
                )

        context.wrap_socket.assert_called_once_with(
            raw_socket,
            server_hostname="example.test",
        )

    def test_tls_probe_disables_certificate_verification(self):
        raw_socket = MagicMock()
        tls_socket = MagicMock()

        tls_socket.version.return_value = "TLSv1.3"
        tls_socket.cipher.return_value = (
            "TLS_AES_256_GCM_SHA384",
            "TLSv1.3",
            256,
        )
        tls_socket.getpeercert.return_value = {}

        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = (
            tls_socket
        )

        with patch(
            "nightrecon.tls_detection.socket.create_connection",
            return_value=raw_socket,
        ):
            with patch(
                "nightrecon.tls_detection.ssl.create_default_context",
                return_value=context,
            ):
                probe_tls_service(
                    address="127.0.0.1",
                    port=443,
                    timeout=1.0,
                )

        self.assertFalse(context.check_hostname)
        self.assertEqual(
        context.verify_mode,
        ssl.CERT_NONE,
    )

    def test_certificate_name_is_formatted(self):
        name = (
            (("countryName", "GB"),),
            (("organizationName", "NightRecon Labs"),),
            (("commonName", "example.test"),),
        )

        result = format_certificate_name(name)

        self.assertEqual(
            result,
            "countryName=GB, organizationName=NightRecon Labs, "
            "commonName=example.test",
        )

    def test_tls_probe_captures_certificate_subject_and_issuer(self):
        raw_socket = MagicMock()
        tls_socket = MagicMock()

        tls_socket.version.return_value = "TLSv1.3"
        tls_socket.cipher.return_value = (
            "TLS_AES_256_GCM_SHA384",
            "TLSv1.3",
            256,
        )
        tls_socket.getpeercert.return_value = (
            b"fake-der-certificate"
        )

        certificate = MagicMock()
        certificate.subject.rfc4514_string.return_value = (
            "CN=example.test"
        )
        certificate.issuer.rfc4514_string.return_value = (
           "O=NightRecon Test CA"
        )

        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = (
            tls_socket
        )

        with patch(
            "nightrecon.tls_detection.socket.create_connection",
            return_value=raw_socket,
        ):
            with patch(
                "nightrecon.tls_detection.ssl.create_default_context",
                return_value=context,
            ):
                with patch(
                    "nightrecon.tls_detection.x509.load_der_x509_certificate",
                    return_value=certificate,
                ):
                    result = probe_tls_service(
                        address="127.0.0.1",
                        port=443,
                        timeout=2.0,
                    )

        self.assertEqual(
            result.certificate_subject,
            "CN=example.test",
        )
        self.assertEqual(
            result.certificate_issuer,
            "O=NightRecon Test CA",
        )

    def test_tls_handshake_error_returns_empty_metadata(self):
        raw_socket = MagicMock()

        context = MagicMock()
        context.wrap_socket.side_effect = ssl.SSLError(
            "TLS handshake failed"
        )

        with patch(
            "nightrecon.tls_detection.socket.create_connection",
            return_value=raw_socket,
        ):
            with patch(
                "nightrecon.tls_detection.ssl.create_default_context",
                return_value=context,
            ):
                result = probe_tls_service(
                    address="127.0.0.1",
                    port=443,
                    timeout=1.0,
                )

        self.assertEqual(result.tls_version, "")
        self.assertEqual(result.cipher, "")
        self.assertEqual(result.certificate_subject, "")
        self.assertEqual(result.certificate_issuer, "")

        raw_socket.close.assert_called_once()

    def test_tls_probe_connection_error_returns_empty_metadata(self):
        with patch(
            "nightrecon.tls_detection.socket.create_connection",
            side_effect=OSError(
                10061,
                "Connection refused",
            ),
        ):
            result = probe_tls_service(
                address="127.0.0.1",
                port=443,
                timeout=1.0,
            )

        self.assertEqual(result.tls_version, "")
        self.assertEqual(result.cipher, "")
        self.assertEqual(result.certificate_subject, "")
        self.assertEqual(result.certificate_issuer, "")

    def test_tls_probe_captures_version_and_cipher(self):
        raw_socket = MagicMock()
        tls_socket = MagicMock()

        tls_socket.version.return_value = "TLSv1.3"
        tls_socket.cipher.return_value = (
            "TLS_AES_256_GCM_SHA384",
            "TLSv1.3",
            256,
        )
        tls_socket.getpeercert.return_value = b""

        context = MagicMock()
        context.wrap_socket.return_value.__enter__.return_value = (
            tls_socket
        )

        with patch(
            "nightrecon.tls_detection.socket.create_connection",
            return_value=raw_socket,
        ) as create_connection:
            with patch(
                "nightrecon.tls_detection.ssl.create_default_context",
                return_value=context,
            ):
                result = probe_tls_service(
                    address="127.0.0.1",
                    port=443,
                    timeout=2.0,
                )

        self.assertEqual(result.tls_version, "TLSv1.3")
        self.assertEqual(
            result.cipher,
            "TLS_AES_256_GCM_SHA384",
        )
        self.assertEqual(result.certificate_subject, "")
        self.assertEqual(result.certificate_issuer, "")

        create_connection.assert_called_once_with(
            ("127.0.0.1", 443),
            timeout=2.0,
        )

    def test_tls_metadata_stores_observation(self):
        metadata = TlsMetadata(
            tls_version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            certificate_subject="example.test",
            certificate_issuer="NightRecon Test CA",
        )

        self.assertEqual(metadata.tls_version, "TLSv1.3")
        self.assertEqual(
            metadata.cipher,
            "TLS_AES_256_GCM_SHA384",
        )
        self.assertEqual(
            metadata.certificate_subject,
            "example.test",
        )
        self.assertEqual(
            metadata.certificate_issuer,
            "NightRecon Test CA",
        )


if __name__ == "__main__":
    unittest.main()
