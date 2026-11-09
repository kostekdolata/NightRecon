import unittest

from nightrecon_red_engine.offline_tool_correlation import OfflineCorrelationError
from nightrecon_red_engine.tier1_offline_evidence import review_tier1_offline_evidence
from nightrecon_red_engine.offline_evidence_benchmark import benchmark_offline_evidence


def artifact(tool, host, digest):
    return {"source_tool": tool, "source_name": "fixture.json",
            "sha256": digest, "authority": "untrusted_offline_import",
            "record_count": 1, "observations": [{
                "classification": "unverified_tool_observation",
                "name" if tool == "Amass" else "host": host,
            }]}


class OfflineEvidenceBenchmarkTests(unittest.TestCase):
    def review(self):
        return review_tier1_offline_evidence(
            imports=(artifact("Amass", "lab.example", "a" * 64),
                     artifact("ProjectDiscovery httpx", "lab.example", "b" * 64)),
            targets=("lab.example",), allowed_targets=("lab.example",),
            capabilities={}, engagement_authorized=True)

    def test_precision_recall_and_reproducibility(self):
        kwargs = {"expected_pairs": (("lab.example", "Amass"),
                                     ("lab.example", "Greenbone/OpenVAS")),
                  "allowed_hosts": ("lab.example",)}
        first = benchmark_offline_evidence(self.review(), **kwargs)
        self.assertEqual(first, benchmark_offline_evidence(self.review(), **kwargs))
        self.assertEqual((first["true_positive_pairs"], first["false_positive_pairs"],
                          first["false_negative_pairs"]), (1, 1, 1))
        self.assertEqual((first["precision"], first["recall"]), (0.5, 0.5))
        self.assertEqual(first["fixture_type"], "synthetic_only")

    def test_undefined_denominators_are_null(self):
        report = self.review()
        report["report"]["hosts"] = []
        report["report"]["host_count"] = 0
        report["report"]["observation_count"] = 0
        result = benchmark_offline_evidence(report, expected_pairs=(),
                                            allowed_hosts=("lab.example",))
        self.assertIsNone(result["precision"])
        self.assertIsNone(result["recall"])

    def test_scope_and_provenance_fail_closed(self):
        report = self.review()
        with self.assertRaises(OfflineCorrelationError):
            benchmark_offline_evidence(report, expected_pairs=(("other.example", "Amass"),),
                                       allowed_hosts=("lab.example",))
        report["report"]["hosts"][0]["evidence"][0]["artifact_sha256"] = "bad"
        with self.assertRaises(OfflineCorrelationError):
            benchmark_offline_evidence(report, expected_pairs=(),
                                       allowed_hosts=("lab.example",))

    def test_budget_and_verdict_fail_closed(self):
        report = self.review()
        with self.assertRaises(OfflineCorrelationError):
            benchmark_offline_evidence(report, expected_pairs=(),
                                       allowed_hosts=("lab.example",), max_pairs=1)
        report["report"]["hosts"][0]["finding_status"] = "confirmed"
        with self.assertRaises(OfflineCorrelationError):
            benchmark_offline_evidence(report, expected_pairs=(),
                                       allowed_hosts=("lab.example",))


if __name__ == "__main__":
    unittest.main()
