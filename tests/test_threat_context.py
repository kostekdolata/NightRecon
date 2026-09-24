"""Tests for NightRecon threat-context intelligence."""

import unittest

from nightrecon.threat_context import (
    EpssRecord,
    KevRecord,
    ThreatContextResult,
    ThreatContextSummary,
    enrich_threat_context,
    summarize_threat_context,
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

    def test_threat_context_summary_is_descriptive(self):
        results = (
            ThreatContextResult(
                vulnerability_id="CVE-2026-1000",
                known_exploited=True,
                epss_probability=0.42,
                epss_percentile=0.97,
                epss_date="2026-09-24",
            ),
            ThreatContextResult(
                vulnerability_id="CVE-2026-1001",
                known_exploited=False,
                epss_probability=0.12,
                epss_percentile=0.65,
                epss_date="2026-09-24",
                errors=("cisa-kev: unavailable",),
            ),
            ThreatContextResult(
                vulnerability_id="CVE-2026-1002",
                errors=("cisa-kev: unavailable",),
            ),
        )

        summary = summarize_threat_context(results)

        self.assertEqual(
            summary,
            ThreatContextSummary(
                cves_enriched=3,
                known_exploited_count=1,
                epss_available_count=2,
                provider_error_count=1,
                max_epss_probability=0.42,
                max_epss_percentile=0.97,
            ),
        )

    def test_empty_threat_context_summary_is_zeroed(self):
        self.assertEqual(
            summarize_threat_context(()),
            ThreatContextSummary(
                cves_enriched=0,
                known_exploited_count=0,
                epss_available_count=0,
                provider_error_count=0,
                max_epss_probability=None,
                max_epss_percentile=None,
            ),
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
