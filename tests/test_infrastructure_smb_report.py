"""Tests for secret-free SMB infrastructure reporting."""

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
    SmbInfrastructureAssessmentReport,
)
from nightrecon.session import ScanSession
from nightrecon.targets import parse_target


class SmbInfrastructureReportTests(unittest.TestCase):
    def test_report_contains_bounded_non_secret_smb_metadata(self):
        session = ScanSession.create(
            target=parse_target(
                "server.example.test"
            ),
            scope_rules=(
                "server.example.test",
            ),
        )
        result = InfrastructureExecutionResult(
            success=True,
            reason="completed",
            target="server.example.test",
            transport=InfrastructureTransport.SMB,
            action_id="smb.server_identity",
            credential_id="corp-readonly",
            state=InfrastructureActionState(
                actions_used=1,
                max_actions=2,
            ),
            facts=(
                InfrastructureFact(
                    key="smb.server_name",
                    value="FILE01",
                ),
            ),
        )
        report = SmbInfrastructureAssessmentReport.create(
            session=session,
            username="audit-user",
            domain="EXAMPLE",
            port=445,
            max_actions=2,
            max_shares=64,
            records=(
                InfrastructureActionRecord.from_result(
                    result
                ),
            ),
        )
        data = report.to_dict()

        self.assertEqual(
            data["transport"],
            "smb",
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
        self.assertEqual(
            data["max_shares"],
            64,
        )
        self.assertNotIn(
            "password",
            repr(
                data
            ).lower(),
        )
        self.assertNotIn(
            "source_name",
            repr(
                data
            ),
        )


if __name__ == "__main__":
    unittest.main()
