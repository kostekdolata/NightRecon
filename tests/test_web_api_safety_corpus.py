"""Tests for the deterministic web/API safety regression corpus."""

import unittest

from nightrecon.web_api_safety_corpus import run_web_api_safety_corpus


class WebApiSafetyCorpusTests(unittest.TestCase):
    def test_fixed_policy_corpus_passes_without_network_activity(self):
        result = run_web_api_safety_corpus()

        self.assertTrue(result.passed)
        self.assertEqual(result.total_cases, 8)
        self.assertEqual(result.matched_cases, 8)
        self.assertEqual(result.unexpected_cases, 0)
        self.assertEqual(len(result.fingerprint), 64)
        self.assertIn("not a Burp/ZAP parity claim", result.interpretation)

    def test_corpus_covers_cross_origin_mutation_and_budget_denials(self):
        result = run_web_api_safety_corpus()
        outcomes = {
            (item.surface, item.name): (item.actual_allowed, item.actual_reason)
            for item in result.cases
        }

        for surface in ("browser", "api"):
            self.assertEqual(
                outcomes[(surface, "mutating-post")],
                (False, "method_not_allowed"),
            )
            self.assertEqual(
                outcomes[(surface, "cross-origin-get")],
                (False, "outside_authorized_origin"),
            )
            self.assertEqual(
                outcomes[(surface, "request-budget-exhausted")],
                (False, "request_budget_exhausted"),
            )


if __name__ == "__main__":
    unittest.main()
