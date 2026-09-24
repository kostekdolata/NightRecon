"""Tests for structured NightRecon software identity."""

import unittest

from nightrecon.software_identity import (
    SoftwareIdentity,
    parse_http_server_identity,
)


class SoftwareIdentityTests(unittest.TestCase):
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
