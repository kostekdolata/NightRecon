"""Tests for the stable engagement export surface."""

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
from nightrecon_red_engine.network_engagement_export import (
    build_network_engagement_export,
)
from nightrecon_red_engine.network_evidence_concentration import (
    build_network_evidence_concentration,
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


class NetworkEngagementExportTests(unittest.TestCase):
    def test_export_composes_high_level_surfaces(self):
        bundles = (bundle("host-a"), bundle("host-b"))
        executive = build_network_engagement_executive(bundles)
        readiness = build_network_review_readiness(bundles)
        plan = build_network_follow_up_plan(bundles)
        concentration = build_network_evidence_concentration(bundles)
        brief = build_network_engagement_brief(
            executive=executive,
            readiness=readiness,
            follow_up_plan=plan,
        )

        result = build_network_engagement_export(
            brief=brief,
            readiness=readiness,
            concentration=concentration,
            follow_up_plan=plan,
        )
        payload = result.to_dict()

        self.assertIn("brief", payload)
        self.assertIn("readiness", payload)
        self.assertIn("concentration", payload)
        self.assertIn("follow_up_plan", payload)
        self.assertIsNone(payload["change"])
        self.assertNotIn("risk_score", str(payload).lower())


if __name__ == "__main__":
    unittest.main()
