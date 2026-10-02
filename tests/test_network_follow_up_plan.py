"""Tests for engagement network follow-up planning."""

import unittest

from nightrecon_red_engine.network_assessment_bundle import (
    build_network_assessment_bundle,
)
from nightrecon_red_engine.network_follow_up_plan import (
    build_network_follow_up_plan,
)
from nightrecon_red_engine.service_detection import ServiceDetectionResult
from nightrecon_red_engine.tcp_scanner import TcpPortResult


def web_bundle(host):
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


class NetworkFollowUpPlanTests(unittest.TestCase):
    def test_recurring_actions_include_host_evidence(self):
        result = build_network_follow_up_plan(
            (web_bundle("host-a"), web_bundle("host-b"))
        )

        self.assertTrue(result.actions)
        self.assertTrue(any(
            item.host_count == 2
            and item.hosts == ("host-a", "host-b")
            for item in result.actions
        ))
        self.assertIn(
            "not by exploitability",
            result.interpretation,
        )

    def test_max_actions_is_bounded(self):
        result = build_network_follow_up_plan(
            (web_bundle("host-a"),),
            max_actions=1,
        )

        self.assertLessEqual(len(result.actions), 1)

    def test_invalid_bound_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "max_actions"):
            build_network_follow_up_plan((), max_actions=0)


if __name__ == "__main__":
    unittest.main()
