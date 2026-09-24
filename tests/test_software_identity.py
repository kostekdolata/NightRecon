"""Tests for structured NightRecon software identity."""

import unittest

from nightrecon.software_identity import (
    SoftwareIdentity,
    parse_http_server_identity,
    parse_ssh_banner_identity,
)


class SoftwareIdentityTests(unittest.TestCase):
    def test_openssh_banner_product_and_version_are_extracted(self):
        result = parse_ssh_banner_identity(
            "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5"
        )

        self.assertEqual(
            result,
            SoftwareIdentity(
                product="OpenSSH",
                version="9.6p1",
                source="banner",
                evidence=(
                    "SSH-2.0-OpenSSH_9.6p1 "
                    "Ubuntu-3ubuntu13.5"
                ),
            ),
        )

    def test_ssh_banner_without_explicit_supported_version_is_not_guessed(self):
        result = parse_ssh_banner_identity(
            "SSH-2.0-libssh"
        )

        self.assertIsNone(result)

    def test_http_server_product_and_version_are_extracted(self):
        result = parse_http_server_identity(
            "nginx/1.24.0"
        )

        self.assertEqual(
            result,
            SoftwareIdentity(
                product="nginx",
                version="1.24.0",
                source="http-server",
                evidence="nginx/1.24.0",
            ),
        )

    def test_http_server_extra_details_do_not_change_identity(self):
        result = parse_http_server_identity(
            "Apache/2.4.58 (Unix)"
        )

        self.assertEqual(
            result,
            SoftwareIdentity(
                product="Apache",
                version="2.4.58",
                source="http-server",
                evidence="Apache/2.4.58 (Unix)",
            ),
        )

    def test_http_server_without_explicit_version_is_not_guessed(self):
        result = parse_http_server_identity("nginx")

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
