"""Tests for deep service fingerprinting."""

import unittest

from nightrecon.service_fingerprint import (
    ServiceFingerprint,
    fingerprint_banner,
    fingerprint_http_server,
)


class DeepServiceFingerprintTests(unittest.TestCase):
    def test_openssh_banner_extracts_protocol_product_version_and_platform(self):
        result = fingerprint_banner(
            "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.14"
        )

        self.assertEqual(
            result,
            ServiceFingerprint(
                protocol="ssh",
                protocol_version="2.0",
                product="OpenSSH",
                version="9.6p1",
                platform="Ubuntu",
                source="banner",
                evidence=(
                    "SSH-2.0-OpenSSH_9.6p1 "
                    "Ubuntu-3ubuntu13.14"
                ),
                confidence="high",
            ),
        )

    def test_proftpd_banner_extracts_product_version(self):
        result = fingerprint_banner(
            "220 ProFTPD 1.3.7 Server"
        )

        self.assertEqual(
            result,
            ServiceFingerprint(
                protocol="ftp",
                product="ProFTPD",
                version="1.3.7",
                source="banner",
                evidence="220 ProFTPD 1.3.7 Server",
                confidence="high",
            ),
        )

    def test_postfix_banner_extracts_product_without_guessing_version(self):
        result = fingerprint_banner(
            "220 mail.example.test ESMTP Postfix"
        )

        self.assertEqual(
            result,
            ServiceFingerprint(
                protocol="smtp",
                product="Postfix",
                source="banner",
                evidence=(
                    "220 mail.example.test ESMTP Postfix"
                ),
                confidence="high",
            ),
        )

    def test_http_server_extracts_platform_hint(self):
        result = fingerprint_http_server(
            "Apache/2.4.58 (Ubuntu)"
        )

        self.assertEqual(
            result,
            ServiceFingerprint(
                protocol="http",
                product="Apache",
                version="2.4.58",
                platform="Ubuntu",
                source="http-server",
                evidence="Apache/2.4.58 (Ubuntu)",
                confidence="high",
            ),
        )

    def test_unknown_banner_returns_none(self):
        self.assertIsNone(
            fingerprint_banner("Welcome")
        )


if __name__ == "__main__":
    unittest.main()
