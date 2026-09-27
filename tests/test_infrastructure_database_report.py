"""Tests for secret-free database infrastructure reporting."""

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
    DatabaseInfrastructureAssessmentReport,
    InfrastructureActionRecord,
)
from nightrecon.session import ScanSession
from nightrecon.storage import ResultStore
from nightrecon.targets import parse_target


class DatabaseInfrastructureReportTests(unittest.TestCase):
    def test_report_contains_bounded_non_secret_database_metadata(self):
        session = ScanSession.create(
            target=parse_target("db01.example.test"),
            scope_rules=("db01.example.test",),
        )
        result = InfrastructureExecutionResult(
            success=True,
            reason="completed",
            target="db01.example.test",
            transport=InfrastructureTransport.DATABASE,
            action_id="database.server_identity",
            credential_id="database-readonly",
            state=InfrastructureActionState(
                actions_used=1,
                max_actions=2,
            ),
            facts=(
                InfrastructureFact(
                    key="database.version",
                    value="17.2",
                ),
            ),
        )
        report = DatabaseInfrastructureAssessmentReport.create(
            session=session,
            engine="postgresql",
            username="audit-user",
            database_name="postgres",
            port=5432,
            max_actions=2,
            max_schemas=64,
            records=(
                InfrastructureActionRecord.from_result(result),
            ),
        )
        data = report.to_dict()

        self.assertEqual(data["transport"], "database")
        self.assertEqual(data["engine"], "postgresql")
        self.assertEqual(data["authentication"], "password")
        self.assertTrue(data["tls_required"])
        self.assertEqual(data["certificate_validation"], "required")
        self.assertEqual(data["max_schemas"], 64)
        self.assertEqual(data["summary"]["selected_actions"], 1)
        self.assertEqual(data["summary"]["attempted_actions"], 1)
        self.assertEqual(data["summary"]["successful_actions"], 1)
        serialized = repr(data).lower()
        self.assertNotIn("source_name", serialized)
        self.assertNotIn("password_env", serialized)
        self.assertNotIn("query", serialized)

    def test_database_report_is_persisted_separately_without_secrets(self):
        session = ScanSession.create(
            target=parse_target("db02.example.test"),
            scope_rules=("db02.example.test",),
        )
        report = DatabaseInfrastructureAssessmentReport.create(
            session=session,
            engine="mysql",
            username="audit-user",
            database_name="mysql",
            port=3306,
            max_actions=2,
            max_schemas=32,
            records=(),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            output = ResultStore(
                temp_dir
            ).save_infrastructure_assessment_report(report)
            self.assertEqual(
                output.name,
                f"{session.session_id}-infrastructure.json",
            )
            with output.open("r", encoding="utf-8") as file:
                data = json.load(file)

        self.assertEqual(data["engine"], "mysql")
        self.assertEqual(data["database_name"], "mysql")
        self.assertNotIn("password", data)
        self.assertNotIn("source_name", data)
        self.assertNotIn("query", repr(data).lower())


if __name__ == "__main__":
    unittest.main()
