"""Tests for NightRecon safe-active DAST reporting and persistence."""

import tempfile
import unittest

from nightrecon.dast_evidence import (
    build_dast_evidence,
    fingerprint_response,
)
from nightrecon.dast_findings import DastFinding
from nightrecon.dast_policy import (
    DastBudgetPolicy,
    DastBudgetState,
    DastCheckDefinition,
)
from nightrecon.dast_report import DastAssessmentReport
from nightrecon.session import ScanSession
from nightrecon.storage import ResultStore
from nightrecon.targets import parse_target


class DastReportTests(unittest.TestCase):
    def test_report_is_structured_non_secret_and_saved_separately(self):
        session = ScanSession.create(
            target=parse_target(
                "example.test"
            ),
            scope_rules=(
                "example.test",
            ),
        )
        check = DastCheckDefinition(
            check_id="web.test",
            name="Test",
            family="cors",
            description="Test.",
            max_requests=2,
            allowed_methods=(
                "OPTIONS",
            ),
        )
        baseline = fingerprint_response(
            status=204,
            content_type="",
            observed_byte_count=0,
            body_sample=b"",
        )
        candidate = fingerprint_response(
            status=204,
            content_type="",
            observed_byte_count=0,
            body_sample=b"",
        )
        evidence = build_dast_evidence(
            check=check,
            target_url=(
                "https://example.test/api"
                "?token=secret"
            ),
            method="OPTIONS",
            request_ordinal=2,
            baseline=baseline,
            candidate=candidate,
        )
        finding = DastFinding(
            check_id="web.test",
            title="Test finding",
            severity="medium",
            target_url=(
                "https://example.test/api"
            ),
            summary="Test summary.",
            evidence=(
                "header_observed=yes",
            ),
        )
        policy = DastBudgetPolicy(
            max_total_requests=4,
            default_family_requests=2,
            family_limits=(
                (
                    "cors",
                    2,
                ),
            ),
        )
        state = DastBudgetState(
            total_used=2,
            check_usage=(
                (
                    "web.test",
                    2,
                ),
            ),
            family_usage=(
                (
                    "cors",
                    2,
                ),
            ),
        )
        report = DastAssessmentReport.create(
            session=session,
            origin="https://example.test",
            enabled_checks=(
                "web.test",
            ),
            policy=policy,
            state=state,
            findings=(
                finding,
            ),
            evidence_records=(
                evidence,
            ),
            errors=(),
        )
        data = report.to_dict()

        self.assertEqual(
            data["summary"]["requests_used"],
            2,
        )
        self.assertEqual(
            data["summary"]["findings"],
            1,
        )
        self.assertEqual(
            data["summary"]["severity_counts"],
            {
                "medium": 1,
            },
        )
        self.assertNotIn(
            "token=secret",
            repr(data),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            store = ResultStore(
                temp_dir
            )
            crawl_path = store.save_session(
                session
            )
            dast_path = store.save_dast_assessment_report(
                report
            )

            self.assertNotEqual(
                crawl_path,
                dast_path,
            )
            self.assertEqual(
                dast_path.name,
                f"{session.session_id}-dast.json",
            )


if __name__ == "__main__":
    unittest.main()
