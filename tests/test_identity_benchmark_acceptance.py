"""Tests for deterministic identity benchmark acceptance."""

import unittest

from nightrecon_red_engine.identity_benchmark import IdentityBenchmarkResult
from nightrecon_red_engine.identity_benchmark_acceptance import (
    build_identity_benchmark_acceptance,
)


def benchmark(**overrides):
    values = dict(
        expected_identities=1,
        discovered_expected_identities=1,
        missed_identities=0,
        invented_identities=0,
        expected_groups=1,
        discovered_expected_groups=1,
        missed_groups=0,
        invented_groups=0,
        expected_memberships=1,
        discovered_expected_memberships=1,
        missed_memberships=0,
        invented_memberships=0,
        expected_roles=0,
        discovered_expected_roles=0,
        missed_roles=0,
        invented_roles=0,
        expected_relationships=0,
        discovered_expected_relationships=0,
        missed_relationships=0,
        invented_relationships=0,
        unresolved_members=0,
        provider_requests=2,
        provider_duration_ms=10,
        truncated=False,
        expected_coverage_complete=True,
        unexpected_evidence_present=False,
        limitations=(),
        missed_reasons=(),
        graph_sha256="a" * 64,
        benchmark_sha256="b" * 64,
    )
    values.update(overrides)
    return IdentityBenchmarkResult(**values)


class IdentityBenchmarkAcceptanceTests(unittest.TestCase):
    def test_fixture_success_does_not_close_external_comparison(self):
        result = build_identity_benchmark_acceptance(benchmark())

        self.assertEqual(result.fixture_gate, "fixture-passed")
        self.assertTrue(result.external_comparison_required)
        self.assertIn("does not establish specialist-tool parity", result.summary)

    def test_missed_or_invented_evidence_requires_review(self):
        result = build_identity_benchmark_acceptance(
            benchmark(
                missed_relationships=1,
                invented_roles=1,
                expected_coverage_complete=False,
                unexpected_evidence_present=True,
            )
        )

        self.assertEqual(result.fixture_gate, "needs-review")
        self.assertEqual(result.missed_evidence, 1)
        self.assertEqual(result.invented_evidence, 1)


if __name__ == "__main__":
    unittest.main()
