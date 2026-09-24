"""Tests for NightRecon built-in passive assessment checks."""

import unittest

from nightrecon.assessment_engine import (
    AssessmentContext,
    CheckIntrusiveness,
)
from nightrecon.builtin_checks import builtin_checks
from nightrecon.service_detection import ServiceDetectionResult


class BuiltinAssessmentCheckTests(unittest.TestCase):
    def test_builtin_checks_are_passive(self):
        self.assertTrue(builtin_checks())

        for check in builtin_checks():
            self.assertEqual(
                check.metadata.intrusiveness,
                CheckIntrusiveness.PASSIVE,
            )

    def test_missing_security_headers_check_uses_observed_evidence(self):
        check = next(
            item
            for item in builtin_checks()
            if item.metadata.check_id
            == "web.security_headers.missing"
        )
        service = ServiceDetectionResult(
            address="127.0.0.1",
            port=443,
            service="https",
            banner="",
            security_headers_present=(
                "content-security-policy",
            ),
            security_headers_missing=(
                "strict-transport-security",
                "x-frame-options",
            ),
        )

        findings = check.run(
            AssessmentContext(
                target="example.test",
                address="127.0.0.1",
                port=443,
                service="https",
                authorized=True,
                service_result=service,
            )
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].check_id,
            "web.security_headers.missing",
        )
        self.assertIn(
            "strict-transport-security",
            findings[0].evidence[0],
        )
        self.assertIn(
            "x-frame-options",
            findings[0].evidence[0],
        )

    def test_missing_security_headers_check_is_quiet_when_none_missing(self):
        check = next(
            item
            for item in builtin_checks()
            if item.metadata.check_id
            == "web.security_headers.missing"
        )
        service = ServiceDetectionResult(
            address="127.0.0.1",
            port=443,
            service="https",
            banner="",
            security_headers_missing=(),
        )

        findings = check.run(
            AssessmentContext(
                target="example.test",
                address="127.0.0.1",
                port=443,
                service="https",
                authorized=True,
                service_result=service,
            )
        )

        self.assertEqual(findings, ())

    def test_legacy_tls_check_flags_observed_tls_1_1(self):
        check = next(
            item
            for item in builtin_checks()
            if item.metadata.check_id
            == "tls.legacy_protocol"
        )
        service = ServiceDetectionResult(
            address="127.0.0.1",
            port=443,
            service="https",
            banner="",
            tls_version="TLSv1.1",
        )

        findings = check.run(
            AssessmentContext(
                target="example.test",
                address="127.0.0.1",
                port=443,
                service="https",
                authorized=True,
                service_result=service,
            )
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(
            findings[0].evidence,
            ("tls_version=TLSv1.1",),
        )

    def test_legacy_tls_check_accepts_tls_1_2_and_newer(self):
        check = next(
            item
            for item in builtin_checks()
            if item.metadata.check_id
            == "tls.legacy_protocol"
        )

        for version in ("TLSv1.2", "TLSv1.3"):
            service = ServiceDetectionResult(
                address="127.0.0.1",
                port=443,
                service="https",
                banner="",
                tls_version=version,
            )

            findings = check.run(
                AssessmentContext(
                    target="example.test",
                    address="127.0.0.1",
                    port=443,
                    service="https",
                    authorized=True,
                    service_result=service,
                )
            )

            self.assertEqual(findings, ())


if __name__ == "__main__":
    unittest.main()
