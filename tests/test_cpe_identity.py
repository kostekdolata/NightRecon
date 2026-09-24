"""Tests for deterministic CPE identity construction."""

import unittest

from nightrecon.cpe_identity import (
    CpeIdentity,
    cpe_identity_from_software,
)
from nightrecon.software_identity import SoftwareIdentity


class CpeIdentityTests(unittest.TestCase):
    def test_nginx_identity_maps_to_canonical_cpe(self):
        software = SoftwareIdentity(
            product="nginx",
            version="1.24.0",
            source="http-server",
            evidence="nginx/1.24.0",
        )

        result = cpe_identity_from_software(software)

        self.assertEqual(
            result,
            CpeIdentity(
                part="a",
                vendor="nginx",
                product="nginx",
                version="1.24.0",
            ),
        )
        self.assertEqual(
            result.to_cpe23(),
            "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
        )

    def test_apache_identity_maps_to_http_server_cpe(self):
        software = SoftwareIdentity(
            product="Apache",
            version="2.4.58",
            source="http-server",
            evidence="Apache/2.4.58 (Unix)",
        )

        result = cpe_identity_from_software(software)

        self.assertEqual(
            result,
            CpeIdentity(
                part="a",
                vendor="apache",
                product="http_server",
                version="2.4.58",
            ),
        )

    def test_openssh_patch_suffix_maps_to_cpe_update(self):
        software = SoftwareIdentity(
            product="OpenSSH",
            version="9.6p1",
            source="banner",
            evidence="SSH-2.0-OpenSSH_9.6p1",
        )

        result = cpe_identity_from_software(software)

        self.assertEqual(
            result,
            CpeIdentity(
                part="a",
                vendor="openbsd",
                product="openssh",
                version="9.6",
                update="p1",
            ),
        )
        self.assertEqual(
            result.to_cpe23(),
            "cpe:2.3:a:openbsd:openssh:9.6:p1:*:*:*:*:*:*",
        )

    def test_unsupported_product_does_not_guess_cpe(self):
        software = SoftwareIdentity(
            product="ExampleServer",
            version="1.0",
            source="http-server",
            evidence="ExampleServer/1.0",
        )

        self.assertIsNone(
            cpe_identity_from_software(software)
        )


if __name__ == "__main__":
    unittest.main()
