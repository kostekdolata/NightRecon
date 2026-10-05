"""Tests for NightRecon credentialed infrastructure reporting."""

import json
import tempfile
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
    InfrastructureAssessmentReport,
    SmbInfrastructureAssessmentReport,
)
from nightrecon.session import ScanSession
from nightrecon.storage import ResultStore
from nightrecon.targets import parse_target


class InfrastructureReportTests(unittest.TestCase):
    def test_report_contains_typed_facts_without_secret_source_metadata(self):
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
            transport=InfrastructureTransport.SSH,
            action_id="ssh.system_identity",
            credential_id="corp-readonly",
            state=InfrastructureActionState(
                actions_used=1,
                max_actions=2,
            ),
            facts=(
                InfrastructureFact(
                    key="system.name",
                    value="Linux",
                ),
            ),
        )
        report = InfrastructureAssessmentReport.create(
            session=session,
            transport="ssh",
            username="audit-user",
            port=22,
            max_actions=2,
            records=(
                InfrastructureActionRecord.from_result(
                    result
                ),
            ),
        )
        data = report.to_dict()
        serialized = json.dumps(
            data,
            sort_keys=True,
        )

        self.assertEqual(
            data["summary"],
            {
                "selected_actions": 1,
                "attempted_actions": 1,
                "successful_actions": 1,
                "failed_actions": 0,
            },
        )
        self.assertEqual(
            data["host_key_policy"],
            "reject",
        )
        self.assertIn(
            "Linux",
            serialized,
        )
        self.assertNotIn(
            "password_env",
            serialized,
        )
        self.assertNotIn(
            "known_hosts",
            serialized,
        )
        self.assertNotIn(
            "secret",
            serialized.lower(),
        )

    def test_smb_report_status_reflects_action_outcomes(self):
        session = ScanSession.create(
            target=parse_target(
                "server.example.test"
            ),
            scope_rules=(
                "server.example.test",
            ),
        )

        def record(
            action_id,
            success,
            reason,
            used,
        ):
            return InfrastructureActionRecord(
                target="server.example.test",
                transport="smb",
                action_id=action_id,
                credential_id="readonly",
                success=success,
                reason=reason,
                facts=(),
                actions_used_after=used,
            )

        successful = SmbInfrastructureAssessmentReport.create(
            session=session,
            username="audit-user",
            domain="EXAMPLE",
            port=445,
            max_actions=4,
            max_shares=128,
            records=(
                record(
                    "smb.server_identity",
                    True,
                    "completed",
                    1,
                ),
                record(
                    "smb.share_inventory",
                    True,
                    "completed",
                    2,
                ),
            ),
        )
        partial = SmbInfrastructureAssessmentReport.create(
            session=session,
            username="audit-user",
            domain="EXAMPLE",
            port=445,
            max_actions=4,
            max_shares=128,
            records=(
                record(
                    "smb.server_identity",
                    True,
                    "completed",
                    1,
                ),
                record(
                    "smb.share_inventory",
                    False,
                    "session_failed",
                    2,
                ),
            ),
        )
        failed = SmbInfrastructureAssessmentReport.create(
            session=session,
            username="audit-user",
            domain="EXAMPLE",
            port=445,
            max_actions=4,
            max_shares=128,
            records=(
                record(
                    "smb.server_identity",
                    False,
                    "authentication_failed",
                    1,
                ),
                record(
                    "smb.share_inventory",
                    False,
                    "authentication_failed",
                    2,
                ),
            ),
        )

        self.assertEqual(
            successful.status,
            "completed",
        )
        self.assertEqual(
            partial.status,
            "completed-with-errors",
        )
        self.assertEqual(
            failed.status,
            "failed",
        )

    def test_report_persists_separately(self):
        session = ScanSession.create(
            target=parse_target(
                "server.example.test"
            ),
            scope_rules=(
                "server.example.test",
            ),
        )
        report = InfrastructureAssessmentReport.create(
            session=session,
            transport="ssh",
            username="audit-user",
            port=22,
            max_actions=2,
            records=(),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            path = ResultStore(
                temp_dir
            ).save_infrastructure_assessment_report(
                report
            )

            self.assertEqual(
                path.name,
                f"{session.session_id}-infrastructure.json",
            )

            with path.open(
                "r",
                encoding="utf-8",
            ) as file:
                data = json.load(
                    file
                )

        self.assertEqual(
            data["transport"],
            "ssh",
        )
        self.assertEqual(
            data["summary"]["attempted_actions"],
            0,
        )


if __name__ == "__main__":
    unittest.main()
