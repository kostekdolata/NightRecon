"""Tests for the NightRecon NVD vulnerability provider."""

import io
import json
import unittest
from unittest.mock import patch

from nightrecon.nvd_provider import NvdVulnerabilityProvider
from nightrecon.software_identity import SoftwareIdentity


class NvdVulnerabilityProviderTests(unittest.TestCase):
    def setUp(self):
        self.software = SoftwareIdentity(
            product="nginx",
            version="1.24.0",
            source="http-server",
            evidence="nginx/1.24.0",
        )

    def test_exact_cpe_lookup_parses_nvd_finding(self):
        payload = {
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-1234",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "Example vulnerability.",
                            }
                        ],
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "cvssData": {
                                        "baseScore": 7.5,
                                        "baseSeverity": "HIGH",
                                    }
                                }
                            ]
                        },
                        "references": [
                            {
                                "url": (
                                    "https://example.test/"
                                    "CVE-2026-1234"
                                )
                            }
                        ],
                    }
                }
            ],
        }

        response = io.BytesIO(
            json.dumps(payload).encode("utf-8")
        )

        with patch(
            "nightrecon.nvd_provider.urlopen",
            return_value=response,
        ) as urlopen:
            provider = NvdVulnerabilityProvider(
                timeout=3.0,
            )

            findings = provider.lookup(self.software)

        self.assertEqual(len(findings), 1)

        finding = findings[0]

        self.assertEqual(
            finding.vulnerability_id,
            "CVE-2026-1234",
        )
        self.assertEqual(finding.source, "nvd")
        self.assertEqual(
            finding.summary,
            "Example vulnerability.",
        )
        self.assertEqual(finding.severity, "HIGH")
        self.assertEqual(finding.cvss_score, 7.5)
        self.assertEqual(
            finding.match_basis,
            "exact-cpe-query",
        )
        self.assertEqual(
            finding.matched_identifier,
            (
                "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
            ),
        )
        self.assertEqual(
            finding.references,
            (
                "https://example.test/CVE-2026-1234",
            ),
        )

        request = urlopen.call_args.args[0]

        self.assertIn(
            "https://services.nvd.nist.gov/rest/json/cves/2.0?",
            request.full_url,
        )
        self.assertIn(
            "cpeName=cpe%3A2.3%3Aa%3Anginx%3Anginx"
            "%3A1.24.0%3A%2A%3A%2A%3A%2A%3A%2A%3A%2A"
            "%3A%2A%3A%2A",
            request.full_url,
        )
        self.assertEqual(
            urlopen.call_args.kwargs["timeout"],
            3.0,
        )

    def test_api_key_is_sent_as_request_header(self):
        payload = {
            "resultsPerPage": 0,
            "startIndex": 0,
            "totalResults": 0,
            "vulnerabilities": [],
        }

        response = io.BytesIO(
            json.dumps(payload).encode("utf-8")
        )

        with patch(
            "nightrecon.nvd_provider.urlopen",
            return_value=response,
        ) as urlopen:
            provider = NvdVulnerabilityProvider(
                api_key="test-api-key",
            )

            provider.lookup(self.software)

        request = urlopen.call_args.args[0]
        headers = {
            name.lower(): value
            for name, value in request.header_items()
        }

        self.assertEqual(
            headers["apikey"],
            "test-api-key",
        )

    def test_multiple_nvd_pages_are_collected(self):
        first_payload = {
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 2,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-1000",
                        "descriptions": [],
                        "metrics": {},
                        "references": [],
                    }
                }
            ],
        }
        second_payload = {
            "resultsPerPage": 1,
            "startIndex": 1,
            "totalResults": 2,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-1001",
                        "descriptions": [],
                        "metrics": {},
                        "references": [],
                    }
                }
            ],
        }

        responses = [
            io.BytesIO(
                json.dumps(first_payload).encode("utf-8")
            ),
            io.BytesIO(
                json.dumps(second_payload).encode("utf-8")
            ),
        ]

        with patch(
            "nightrecon.nvd_provider.urlopen",
            side_effect=responses,
        ) as urlopen:
            provider = NvdVulnerabilityProvider()

            findings = provider.lookup(self.software)

        self.assertEqual(
            tuple(
                finding.vulnerability_id
                for finding in findings
            ),
            (
                "CVE-2026-1000",
                "CVE-2026-1001",
            ),
        )
        self.assertEqual(urlopen.call_count, 2)
        second_request = urlopen.call_args_list[1].args[0]
        self.assertIn(
            "startIndex=1",
            second_request.full_url,
        )

    def test_unsupported_software_skips_network_lookup(self):
        software = SoftwareIdentity(
            product="ExampleServer",
            version="1.0",
            source="http-server",
            evidence="ExampleServer/1.0",
        )

        with patch(
            "nightrecon.nvd_provider.urlopen"
        ) as urlopen:
            provider = NvdVulnerabilityProvider()

            findings = provider.lookup(software)

        self.assertEqual(findings, ())
        urlopen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
