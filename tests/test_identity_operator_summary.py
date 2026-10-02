"""Tests for operator-facing identity acceptance synthesis."""

import unittest

from nightrecon_red_engine.identity_benchmark_acceptance import (
    IdentityBenchmarkAcceptance,
)
from nightrecon_red_engine.identity_coverage_review import IdentityCoverageReview
from nightrecon_red_engine.identity_operator_summary import (
    build_identity_operator_summary,
)


class IdentityOperatorSummaryTests(unittest.TestCase):
    def test_summary_preserves_limits_and_actions(self):
        coverage = IdentityCoverageReview(
            level="collected",
            summary="collected",
            identities=2,
            groups=1,
            memberships=1,
            roles=1,
            permissions=0,
            relationships=1,
            relationship_types=(("assigned-role", 1),),
            limitations=(),
            open_acceptance_gates=("external comparison remains open",),
        )
        acceptance = IdentityBenchmarkAcceptance(
            fixture_gate="fixture-passed",
            summary="fixture passed",
            missed_evidence=0,
            invented_evidence=0,
            provider_truncated=False,
            external_comparison_required=True,
            next_actions=("Run live comparison.",),
        )

        result = build_identity_operator_summary(coverage, acceptance)

        self.assertIn("deterministic fixture proof", result.headline)
        self.assertEqual(result.relationship_themes, ("assigned-role: 1",))
        self.assertIn("external comparison remains open", result.limitations)
        self.assertIn(
            "Complete broader read-only ACL/security-descriptor coverage.",
            result.next_actions,
        )


if __name__ == "__main__":
    unittest.main()
