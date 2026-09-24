"""Tests for NightRecon threat-context intelligence."""

import unittest

from nightrecon.threat_context import (
    EpssRecord,
    KevRecord,
    ThreatContextResult,
    enrich_threat_context,
)
from nightrecon.vulnerability_intelligence import (
    ServiceVulnerabilityResult,
    VulnerabilityFinding,
    VulnerabilityLookupResult,
)
from nightrecon.software_identity import SoftwareIdentity


class ThreatContextTests(unittest.TestCase):
    def setUp(self):
        self.software = SoftwareIdentity(
            product="nginx",
            version="1.24.0",
            source="http-server",
            evidence="nginx/1.24.0",
        )

    def test_enrichment_combines_kev_and_epss_by_cve(self):
        findings = (
            VulnerabilityFinding(
                vulnerability_id="CVE-2026-1234",
                source="nvd",
                summary="Example vulnerability.",
            ),
        )
        vulnerabilities = (
            ServiceVulnerabilityResult(
                address="127.0.0.1",
                port=80,
                service="http",
                lookup=VulnerabilityLookupResult(
                    provider="nvd",
                    software_identity=self.software,
                    findings=findings,
                ),
            ),
        )

        class KevProvider:
            name = "cisa-kev"

            def lookup(self, vulnerability_ids):
                self.received = vulnerability_ids
                return {
                    "CVE-2026-1234": KevRecord(
                        vulnerability_id="CVE-2026-1234",
                        date_added="2026-09-01",
                        due_date="2026-09-22",
                        known_ransomware_campaign_use="Known",
                        required_action="Apply vendor mitigations.",
                    ),
                }

        class EpssProvider:
            name = "first-epss"

            def lookup(self, vulnerability_ids):
                self.received = vulnerability_ids
                return {
                    "CVE-2026-1234": EpssRecord(
                        vulnerability_id="CVE-2026-1234",
                        probability=0.42,
                        percentile=0.97,
                        date="2026-09-24",
                    ),
                }

        kev = KevProvider()
        epss = EpssProvider()

        result = enrich_threat_context(
            vulnerabilities=vulnerabilities,
            kev_provider=kev,
            epss_provider=epss,
        )

        self.assertEqual(
            kev.received,
            ("CVE-2026-1234",),
        )
        self.assertEqual(
            epss.received,
            ("CVE-2026-1234",),
        )
        self.assertEqual(
            result,
            (
                ThreatContextResult(
                    vulnerability_id="CVE-2026-1234",
                    known_exploited=True,
                    kev_date_added="2026-09-01",
                    kev_due_date="2026-09-22",
                    kev_known_ransomware_campaign_use="Known",
                    kev_required_action="Apply vendor mitigations.",
                    epss_probability=0.42,
                    epss_percentile=0.97,
                    epss_date="2026-09-24",
                ),
            ),
        )

    def test_provider_errors_are_fail_soft_and_preserved(self):
        findings = (
            VulnerabilityFinding(
                vulnerability_id="CVE-2026-1234",
                source="nvd",
                summary="Example vulnerability.",
            ),
        )
        vulnerabilities = (
            ServiceVulnerabilityResult(
                address="127.0.0.1",
                port=80,
                service="http",
                lookup=VulnerabilityLookupResult(
                    provider="nvd",
                    software_identity=self.software,
                    findings=findings,
                ),
            ),
        )

        class FailingKevProvider:
            name = "cisa-kev"

            def lookup(self, vulnerability_ids):
                raise OSError("KEV unavailable")

        class FailingEpssProvider:
            name = "first-epss"

            def lookup(self, vulnerability_ids):
                raise OSError("EPSS unavailable")

        result = enrich_threat_context(
            vulnerabilities=vulnerabilities,
            kev_provider=FailingKevProvider(),
            epss_provider=FailingEpssProvider(),
        )

        self.assertEqual(
            result,
            (
                ThreatContextResult(
                    vulnerability_id="CVE-2026-1234",
                    errors=(
                        "cisa-kev: KEV unavailable",
                        "first-epss: EPSS unavailable",
                    ),
                ),
            ),
        )

    def test_duplicate_cves_are_looked_up_once(self):
        finding = VulnerabilityFinding(
            vulnerability_id="CVE-2026-1234",
            source="nvd",
            summary="Example vulnerability.",
        )
        vulnerabilities = (
            ServiceVulnerabilityResult(
                address="127.0.0.1",
                port=80,
                service="http",
                lookup=VulnerabilityLookupResult(
                    provider="nvd",
                    software_identity=self.software,
                    findings=(finding,),
                ),
            ),
            ServiceVulnerabilityResult(
                address="127.0.0.1",
                port=443,
                service="https",
                lookup=VulnerabilityLookupResult(
                    provider="nvd",
                    software_identity=self.software,
                    findings=(finding,),
                ),
            ),
        )

        class EmptyProvider:
            name = "empty"

            def __init__(self):
                self.calls = []

            def lookup(self, vulnerability_ids):
                self.calls.append(vulnerability_ids)
                return {}

        kev = EmptyProvider()
        epss = EmptyProvider()

        result = enrich_threat_context(
            vulnerabilities=vulnerabilities,
            kev_provider=kev,
            epss_provider=epss,
        )

        self.assertEqual(
            result,
            (
                ThreatContextResult(
                    vulnerability_id="CVE-2026-1234",
                ),
            ),
        )
        self.assertEqual(
            kev.calls,
            [("CVE-2026-1234",)],
        )
        self.assertEqual(
            epss.calls,
            [("CVE-2026-1234",)],
        )

    def test_epss_values_must_be_probabilities(self):
        with self.assertRaises(ValueError):
            EpssRecord(
                vulnerability_id="CVE-2026-1234",
                probability=1.1,
                percentile=0.5,
            )


if __name__ == "__main__":
    unittest.main()
