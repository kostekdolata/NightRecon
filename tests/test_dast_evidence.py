"""Tests for bounded NightRecon DAST response evidence."""

import unittest

from nightrecon.dast_evidence import (
    build_dast_evidence,
    build_retest_descriptor,
    compare_response_fingerprints,
    fingerprint_response,
    redact_dast_url,
)
from nightrecon.dast_policy import DastCheckDefinition


def _check():
    return DastCheckDefinition(
        check_id="web.response-diff",
        name="Response Difference",
        family="response-diff",
        description="Compare bounded response metadata.",
        max_requests=4,
        allowed_methods=(
            "GET",
        ),
    )


def _fingerprint(
    body,
    *,
    status=200,
    content_type="text/html",
    observed=None,
):
    if observed is None:
        observed = len(
            body
        )

    return fingerprint_response(
        status=status,
        content_type=content_type,
        observed_byte_count=observed,
        body_sample=body,
        max_sample_bytes=8192,
    )


class DastEvidenceTests(unittest.TestCase):
    def test_response_fingerprint_retains_hash_not_body(self):
        secret = (
            b"sensitive-response-value"
        )
        fingerprint = _fingerprint(
            secret
        )

        self.assertEqual(
            fingerprint.sample_byte_count,
            len(secret),
        )
        self.assertEqual(
            len(
                fingerprint.sample_sha256
            ),
            64,
        )
        self.assertNotIn(
            "sensitive-response-value",
            repr(fingerprint),
        )

    def test_fingerprint_sampling_is_bounded_and_marks_truncation(self):
        fingerprint = fingerprint_response(
            status=200,
            content_type="application/json; charset=utf-8",
            observed_byte_count=1000,
            body_sample=b"A" * 512,
            max_sample_bytes=64,
        )

        self.assertEqual(
            fingerprint.sample_byte_count,
            64,
        )
        self.assertTrue(
            fingerprint.sample_truncated
        )
        self.assertEqual(
            fingerprint.content_type,
            "application/json; charset=utf-8",
        )

    def test_status_change_is_material(self):
        difference = compare_response_fingerprints(
            _fingerprint(
                b"same",
                status=200,
            ),
            _fingerprint(
                b"same",
                status=403,
            ),
        )

        self.assertTrue(
            difference.material_difference
        )
        self.assertIn(
            "status_changed",
            difference.strong_signals,
        )

    def test_significant_length_change_is_material(self):
        difference = compare_response_fingerprints(
            _fingerprint(
                b"A" * 100
            ),
            _fingerprint(
                b"B" * 180
            ),
        )

        self.assertTrue(
            difference.significant_length_change
        )
        self.assertTrue(
            difference.material_difference
        )
        self.assertIn(
            "significant_length_change",
            difference.strong_signals,
        )

    def test_hash_only_change_is_weak_to_reduce_dynamic_false_positives(self):
        difference = compare_response_fingerprints(
            _fingerprint(
                b"abcdef"
            ),
            _fingerprint(
                b"abcdeg"
            ),
        )

        self.assertTrue(
            difference.sample_changed
        )
        self.assertFalse(
            difference.material_difference
        )
        self.assertEqual(
            difference.strong_signals,
            (),
        )
        self.assertEqual(
            difference.weak_signals,
            (
                "sample_changed",
            ),
        )

    def test_small_length_and_body_change_remains_weak(self):
        difference = compare_response_fingerprints(
            _fingerprint(
                b"A" * 100
            ),
            _fingerprint(
                b"B" * 105
            ),
        )

        self.assertFalse(
            difference.significant_length_change
        )
        self.assertFalse(
            difference.material_difference
        )
        self.assertEqual(
            difference.weak_signals,
            (
                "sample_changed",
            ),
        )

    def test_evidence_redacts_url_secrets_and_builds_stable_retest_identity(self):
        baseline = _fingerprint(
            b"baseline"
        )
        candidate = _fingerprint(
            b"candidate-response-with-material-size-change" * 4
        )
        first = build_dast_evidence(
            check=_check(),
            target_url=(
                "https://user:secret@example.test/account"
                "?token=hidden#fragment"
            ),
            method="GET",
            request_ordinal=2,
            baseline=baseline,
            candidate=candidate,
        )
        second = build_dast_evidence(
            check=_check(),
            target_url=(
                "https://example.test/account?other=value"
            ),
            method="GET",
            request_ordinal=3,
            baseline=_fingerprint(
                b"different"
            ),
            candidate=_fingerprint(
                b"different-two"
            ),
        )

        self.assertEqual(
            first.target_url,
            "https://example.test/account",
        )
        self.assertEqual(
            first.retest_id,
            second.retest_id,
        )
        self.assertNotIn(
            "user:secret",
            repr(first),
        )
        self.assertNotIn(
            "token=hidden",
            repr(first),
        )

        descriptor = build_retest_descriptor(
            first
        )

        self.assertEqual(
            descriptor.retest_id,
            first.retest_id,
        )
        self.assertEqual(
            descriptor.target_url,
            "https://example.test/account",
        )
        self.assertEqual(
            descriptor.expected_strong_signals,
            first.difference.strong_signals,
        )

    def test_evidence_rejects_method_outside_check_policy(self):
        with self.assertRaises(
            PermissionError
        ):
            build_dast_evidence(
                check=_check(),
                target_url="https://example.test/",
                method="HEAD",
                request_ordinal=1,
                baseline=_fingerprint(
                    b"one"
                ),
                candidate=_fingerprint(
                    b"two"
                ),
            )

    def test_invalid_urls_and_thresholds_fail_closed(self):
        with self.assertRaises(
            ValueError
        ):
            redact_dast_url(
                "/relative"
            )

        with self.assertRaises(
            ValueError
        ):
            compare_response_fingerprints(
                _fingerprint(
                    b"one"
                ),
                _fingerprint(
                    b"two"
                ),
                min_relative_length_change=1.1,
            )

        with self.assertRaises(
            ValueError
        ):
            fingerprint_response(
                status=200,
                content_type="text/plain",
                observed_byte_count=-1,
                body_sample=b"",
            )


if __name__ == "__main__":
    unittest.main()
