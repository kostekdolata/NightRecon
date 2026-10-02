"""Tests for consolidated engagement network briefs."""

import unittest

from nightrecon_red_engine.network_assessment_bundle import (
    build_network_assessment_bundle,
)
from nightrecon_red_engine.network_engagement_brief import (
    build_network_engagement_brief,
)
from nightrecon_red_engine.network_engagement_executive import (
    build_network_engagement_executive,
)
from nightrecon_red_engine.network_follow_up_plan import (
    build_network_follow_up_plan,
)
from nightrecon_red_engine.network_review_readiness import (
    build_network_review_readiness,
)
from nightrecon_red_engine.service_detection import ServiceDetectionResult
from nightrecon_red_engine.tcp_scanner import TcpPortResult


def bundle(host):
    return build_network_assessment_bundle(
        host=host,
        tcp_results=(
            TcpPortResult(
                address=host,
                port=443,
                is_open=True,
                error_code=0,
            ),
        ),
        services=(
            ServiceDetectionResult(
                address=host,
                port=443,
                service="https",
                banner="",
            ),
        ),
    )


class NetworkEngagementBriefTests(unittest.TestCase):
    def test_brief_combines_executive_readiness_and_actions(self):
        bundles = (bundle("host-a"), bundle("host-b"))
        executive = build_network_engagement_executive(bundles)
        readiness = build_network_review_readiness(bundles)
        plan = build_network_follow_up_plan(bundles)

        result = build_network_engagement_brief(
            executive=executive,
            readiness=readiness,
            follow_up_plan=plan,
        )

        self.assertEqual(result.headline, executive.headline)
        self.assertIn("No prior engagement comparison", result.change_summary)
        self.assertTrue(result.follow_up_actions)
        self.assertTrue(result.limitations)
        self.assertNotIn("risk_score", str(result.to_dict()).lower())


if __name__ == "__main__":
    unittest.main()
