"""Offline labeled quality benchmarks, no subprocess or network."""
import json
import unittest

from nightrecon_red_engine.tier1_capability_plan import TIER1
from nightrecon_red_engine.tier1_offline_benchmark import (
    OfflineBenchmarkError, score_synthetic_tier1_benchmark,
)


def fixture(cases):
    return json.dumps({"schema": "red.synthetic_tier1_benchmark_fixture.v1",
                       "synthetic": True, "cases": cases}).encode()


def case(i, tool="nmap", target="127.0.0.1", expected=True, observed=True):
    return {"case_id": f"case-{i}", "tool": tool, "target": target,
            "expected_positive": expected, "observed_positive": observed}


class OfflineBenchmarkTests(unittest.TestCase):
    def score(self, cases, **changes):
        args = dict(engagement_id="lab", authorized_targets=("127.0.0.1",))
        args.update(changes)
        return score_synthetic_tier1_benchmark(fixture(cases), **args)

    def test_confusion_matrix_and_denominator_honesty(self):
        result = self.score([case(1), case(2, expected=False),
                             case(3, expected=False, observed=False),
                             case(4, observed=False)])
        stats = result["by_tool"][0]
        self.assertEqual(tuple(stats[k] for k in ("tp", "fp", "tn", "fn")), (1, 1, 1, 1))
        self.assertEqual(stats["precision"], 0.5)
        self.assertEqual(stats["recall"], 0.5)
        self.assertEqual(stats["false_positive_rate"], 0.5)
        self.assertFalse(result["integration_verified"])
        self.assertEqual(len(result["fixture_sha256"]), 64)
        empty_denominators = self.score([case(5, expected=False, observed=False)])
        self.assertIsNone(empty_denominators["by_tool"][0]["precision"])
        self.assertIsNone(empty_denominators["by_tool"][0]["recall"])

    def test_all_seven_tier1_tools_supported(self):
        result = self.score([case(i, tool=tool) for i, tool in enumerate(TIER1)])
        self.assertEqual({row["tool"] for row in result["by_tool"]}, set(TIER1))
        self.assertEqual(result["case_count"], 7)

    def test_scope_duplicates_and_invalid_cases_fail_closed(self):
        for cases in (
            [case(1), case(1)],
            [case(1, target="127.0.0.2")],
            [case(1, tool="metasploit")],
            [dict(case(1), expected_positive=1)],
            [dict(case(1), observed_positive="true")],
            [dict(case(1), secret="must-not-copy")],
            [],
        ):
            with self.subTest(cases=cases), self.assertRaises(OfflineBenchmarkError):
                self.score(cases)
        with self.assertRaises(OfflineBenchmarkError):
            self.score([case(1)], max_bytes=1)
        with self.assertRaises(OfflineBenchmarkError):
            self.score([case(1), case(2)], max_cases=1)

    def test_untrusted_envelope_rejected(self):
        for raw in (b"{", b"[]", b"{}", b'{"schema":"bad","synthetic":true,"cases":[]}'):
            with self.subTest(raw=raw), self.assertRaises(OfflineBenchmarkError):
                score_synthetic_tier1_benchmark(
                    raw, engagement_id="lab", authorized_targets=("127.0.0.1",)
                )


if __name__ == "__main__":
    unittest.main()
