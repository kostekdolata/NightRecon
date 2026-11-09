import unittest

from nightrecon_red_engine.offline_tool_correlation import (
    OfflineCorrelationError, correlate_offline_hosts,
)
from nightrecon_red_engine.offline_correlation_report import render_offline_correlation_report


def evidence(tool, host, digest):
    return {"source_tool": tool, "source_name": "fixture.json",
            "sha256": digest, "authority": "untrusted_offline_import",
            "record_count": 1, "observations": [{
                "classification": "unverified_tool_observation",
                "name" if tool == "Amass" else "host": host,
            }]}


class TestOfflineCorrelationReport(unittest.TestCase):
    def setUp(self):
        self.correlation = correlate_offline_hosts((
            evidence("Amass", "a.example.org", "a" * 64),
            evidence("ProjectDiscovery httpx", "a.example.org", "b" * 64),
        ), allowed_hosts=("a.example.org",))

    def test_deterministic_provenance_and_honest_status(self):
        first = render_offline_correlation_report(self.correlation)
        self.assertEqual(first, render_offline_correlation_report(self.correlation))
        self.assertEqual(first["host_count"], 1)
        self.assertEqual(first["observation_count"], 2)
        self.assertEqual(first["hosts"][0]["finding_status"], "not_assessed")
        self.assertEqual(first["hosts"][0]["evidence"][0]["artifact_sha256"], "a" * 64)
        self.assertEqual(len(first["report_sha256"]), 64)

    def test_rejects_verdict_promotion_and_corrupt_provenance(self):
        self.correlation["hosts"][0]["verdict"] = "confirmed_exploitable"
        with self.assertRaises(OfflineCorrelationError):
            render_offline_correlation_report(self.correlation)
        self.correlation["hosts"][0]["verdict"] = "not_assessed"
        self.correlation["hosts"][0]["observations"][0]["sha256"] = "bad"
        with self.assertRaises(OfflineCorrelationError):
            render_offline_correlation_report(self.correlation)

    def test_budget_and_count_mismatch_fail_closed(self):
        with self.assertRaises(OfflineCorrelationError):
            render_offline_correlation_report(self.correlation, max_hosts=0)
        with self.assertRaises(OfflineCorrelationError):
            render_offline_correlation_report(self.correlation, max_observations=1)
        self.correlation["observation_count"] = 3
        with self.assertRaises(OfflineCorrelationError):
            render_offline_correlation_report(self.correlation)


if __name__ == "__main__":
    unittest.main()
