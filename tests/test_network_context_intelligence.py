"""Tests for high-level network security-context correlation."""

import unittest

from nightrecon_red_engine.network_context_intelligence import (
    build_network_context_intelligence,
)
from nightrecon_red_engine.software_identity import SoftwareIdentity
from nightrecon_red_engine.threat_context import ThreatContextResult
from nightrecon_red_engine.vulnerability_intelligence import (
    ServiceVulnerabilityResult,
    VulnerabilityFinding,
    VulnerabilityLookupResult,
)


class NetworkContextIntelligenceTests(unittest.TestCase):
    def test_context_correlates_matched_vulnerability_and_kev_evidence(self):
        software = SoftwareIdentity(
            product="example",
            version="1.0",
            source="banner",
            evidence="example/1.0",
        )
        vulnerabilities = (
            ServiceVulnerabilityResult(
                address="192.0.2.10",
                port=443,
                service="https",
                lookup=VulnerabilityLookupResult(
                    provider="nvd",
                    software_identity=software,
                    findings=(
                        VulnerabilityFinding(
                            vulnerability_id="CVE-2026-1234",
                            source="nvd",
                            summary="Example matched record.",
                            severity="HIGH",
                            cvss_score=8.0,
                            match_basis="exact-cpe-query",
                            matched_identifier="cpe:2.3:a:example:example:1.0:*:*:*:*:*:*:*",
                        ),
                    ),
                ),
            ),
        )
        threat = (
            ThreatContextResult(
                vulnerability_id="CVE-2026-1234",
                known_exploited=True,
                epss_probability=0.42,
                epss_percentile=0.97,
            ),
        )

        result = build_network_context_intelligence(
            vulnerability_intelligence_enabled=True,
            vulnerabilities=vulnerabilities,
            threat_context_enabled=True,
            threat_context=threat,
        )

        self.assertEqual(
            result.headline,
            "Network exposure has correlated security context",
        )
        self.assertEqual(result.evidence_quality, "high")
        self.assertTrue(any(
            "1 high" in note for note in result.notable_context
        ))
        self.assertTrue(any(
            "known-exploited" in note for note in result.notable_context
        ))
        self.assertFalse(result.coverage_gaps)

    def test_disabled_providers_are_explicit_coverage_gaps(self):
        result = build_network_context_intelligence(
            vulnerability_intelligence_enabled=False,
            threat_context_enabled=False,
        )

        self.assertEqual(result.evidence_quality, "limited")
        self.assertIn(
            "Vulnerability intelligence was not enabled.",
            result.coverage_gaps,
        )
        self.assertIn(
            "External threat-context enrichment was not enabled.",
            result.coverage_gaps,
        )
        self.assertIn(
            "not proof of exploitability",
            result.interpretation,
        )

    def test_provider_errors_reduce_evidence_quality(self):
        software = SoftwareIdentity(
            product="example",
            version="1.0",
            source="banner",
            evidence="example/1.0",
        )
        result = build_network_context_intelligence(
            vulnerability_intelligence_enabled=True,
            vulnerabilities=(
                ServiceVulnerabilityResult(
                    address="192.0.2.10",
                    port=443,
                    service="https",
                    lookup=VulnerabilityLookupResult(
                        provider="nvd",
                        software_identity=software,
                        error="provider unavailable",
                    ),
                ),
            ),
            threat_context_enabled=True,
            threat_context=(
                ThreatContextResult(
                    vulnerability_id="CVE-2026-1234",
                    errors=("epss: unavailable",),
                ),
            ),
        )

        self.assertEqual(result.evidence_quality, "limited")
        self.assertTrue(any(
            "lookup(s) failed" in gap for gap in result.coverage_gaps
        ))
        self.assertTrue(any(
            "provider error" in gap for gap in result.coverage_gaps
        ))


if __name__ == "__main__":
    unittest.main()
