"""Tests for secret-free WinRM infrastructure reporting."""

import unittest

from nightrecon.infrastructure_execution import (
    InfrastructureExecutionResult,
    InfrastructureFact,
)
from nightrecon.infrastructure_models import (
    InfrastructureActionState,
    InfrastructureTransport,
)
from nightrecon.infrastructure_report import (
    InfrastructureActionRecord,
    WinRmInfrastructureAssessmentReport,
)
from nightrecon.session import ScanSession
from nightrecon.targets import parse_target


class WinRmInfrastructureReportTests(unittest.TestCase):
    def test_report_contains_bounded_non_secret_winrm_metadata(self):
        session = ScanSession.create(
            target=parse_target(
                "win01.example.test"
            ),
            scope_rules=(
                "win01.example.test",
            ),
        )
        result = InfrastructureExecutionResult(
            success=True,
            reason="completed",
            target="win01.example.test",
            transport=InfrastructureTransport.WINRM,
            action_id="winrm.system_identity",
            credential_id="corp-readonly",
            state=InfrastructureActionState(
                actions_used=1,
                max_actions=2,
            ),
            facts=(
                InfrastructureFact(
                    key="windows.hostname",
                    value="WIN01",
                ),
            ),
        )
        report = WinRmInfrastructureAssessmentReport.create(
            session=session,
            username="audit-user",
            port=5986,
            max_actions=2,
            max_patches=64,
            records=(
                InfrastructureActionRecord.from_result(
                    result
                ),
            ),
        )
        data = report.to_dict()

        self.assertEqual(
            data["transport"],
            "winrm",
        )
        self.assertEqual(
            data["authentication"],
            "ntlm",
        )
        self.assertTrue(
            data["tls_required"]
        )
        self.assertEqual(
            data["certificate_validation"],
            "required",
        )
        self.assertEqual(
            data["max_patches"],
            64,
        )
        self.assertEqual(
            data["summary"]["selected_actions"],
            1,
        )
        self.assertEqual(
            data["summary"]["attempted_actions"],
            1,
        )
        self.assertEqual(
            data["summary"]["successful_actions"],
            1,
        )
        serialized = repr(
            data
        ).lower()
        self.assertNotIn(
            "password",
            serialized,
        )
        self.assertNotIn(
            "source_name",
            serialized,
        )


if __name__ == "__main__":
    unittest.main()
