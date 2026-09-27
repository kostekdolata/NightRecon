"""CLI tests for bounded read-only database infrastructure assessment."""

import contextlib
import io
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon.cli import main
from nightrecon.infrastructure_execution import (
    InfrastructureExecutionResult,
    InfrastructureFact,
)
from nightrecon.infrastructure_models import InfrastructureActionState


_SECRET = "cli-database-secret-value"


class CliInfrastructureDatabaseTests(unittest.TestCase):
    def run_cli(self, *args):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch.object(sys, "argv", ["nightrecon", *args]):
            with contextlib.redirect_stdout(stdout):
                with contextlib.redirect_stderr(stderr):
                    try:
                        main()
                        code = 0
                    except SystemExit as exc:
                        code = exc.code
        return code, stdout.getvalue(), stderr.getvalue()

    def test_supported_engines_report_fixed_actions_without_secrets(self):
        def fake_execute(
            *,
            action,
            definition,
            decision,
            state,
            credential,
            adapter,
        ):
            credential.clear()
            return InfrastructureExecutionResult(
                success=True,
                reason="completed",
                target=action.target,
                transport=action.transport,
                action_id=action.action_id,
                credential_id=action.credential_id,
                state=InfrastructureActionState(
                    actions_used=state.actions_used + 1,
                    max_actions=state.max_actions,
                ),
                facts=(
                    InfrastructureFact(
                        key=(
                            "database.engine"
                            if action.action_id == "database.server_identity"
                            else "database.schema_count"
                        ),
                        value=(
                            adapter.profile.engine.value
                            if action.action_id == "database.server_identity"
                            else "2"
                        ),
                    ),
                ),
            )

        for engine, expected_port in (
            ("postgresql", 5432),
            ("mysql", 3306),
        ):
            with self.subTest(engine=engine):
                source_name = f"NIGHTRECON_{engine.upper()}_CLI_SECRET"
                with patch.dict(
                    os.environ,
                    {source_name: _SECRET},
                    clear=False,
                ):
                    with patch(
                        "nightrecon.cli.execute_infrastructure_action",
                        side_effect=fake_execute,
                    ) as execute:
                        with patch("nightrecon.cli.ResultStore") as store_class:
                            store_class.return_value.save_infrastructure_assessment_report.return_value = Path(
                                "results/session-infrastructure.json"
                            )
                            with patch(
                                "nightrecon.cli.NightReconLogger"
                            ) as logger_class:
                                code, stdout, stderr = self.run_cli(
                                    "infra",
                                    "database",
                                    "db01.example.test",
                                    "--scope",
                                    "db01.example.test",
                                    "--engine",
                                    engine,
                                    "--username",
                                    "audit-user",
                                    "--database-name",
                                    "inventory",
                                    "--credential-id",
                                    "database-readonly",
                                    "--password-env",
                                    source_name,
                                    "--action",
                                    "database.server_identity",
                                    "--action",
                                    "database.schema_inventory",
                                    "--max-actions",
                                    "2",
                                    "--max-schemas",
                                    "32",
                                )

                self.assertEqual(code, 0)
                self.assertEqual(stderr, "")
                self.assertEqual(execute.call_count, 2)
                self.assertIn(
                    f"Database Assessment Summary: engine={engine} "
                    "selected=2 attempted=2 successful=2 failed=0",
                    stdout,
                )
                combined = stdout + repr(logger_class.mock_calls)
                self.assertNotIn(_SECRET, combined)
                self.assertNotIn(source_name, combined)
                report = (
                    store_class.return_value
                    .save_infrastructure_assessment_report
                    .call_args.args[0]
                )
                self.assertEqual(report.engine, engine)
                self.assertEqual(report.port, expected_port)
                self.assertTrue(report.tls_required)
                self.assertEqual(
                    report.certificate_validation,
                    "required",
                )
                serialized = repr(report.to_dict())
                self.assertNotIn(_SECRET, serialized)
                self.assertNotIn(source_name, serialized)

    def test_out_of_scope_target_fails_before_credentials_or_execution(self):
        with patch("nightrecon.cli.resolve_credential") as resolve:
            with patch(
                "nightrecon.cli.execute_infrastructure_action"
            ) as execute:
                with patch("nightrecon.cli.NightReconLogger"):
                    code, stdout, stderr = self.run_cli(
                        "infra", "database", "outside.example.test",
                        "--scope", "db01.example.test",
                        "--engine", "postgresql",
                        "--username", "audit-user",
                        "--database-name", "postgres",
                        "--credential-id", "database-readonly",
                        "--password-env", "NIGHTRECON_DATABASE_PASSWORD",
                        "--action", "database.server_identity",
                    )
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("outside the authorized scope", stderr)
        resolve.assert_not_called()
        execute.assert_not_called()

    def test_actions_must_fit_budget_before_credential_resolution(self):
        with patch("nightrecon.cli.resolve_credential") as resolve:
            code, stdout, stderr = self.run_cli(
                "infra", "database", "db01.example.test",
                "--scope", "db01.example.test",
                "--engine", "mysql",
                "--username", "audit-user",
                "--database-name", "mysql",
                "--credential-id", "database-readonly",
                "--password-env", "NIGHTRECON_DATABASE_PASSWORD",
                "--action", "database.server_identity",
                "--action", "database.schema_inventory",
                "--max-actions", "1",
            )
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("exceed max_actions", stderr)
        resolve.assert_not_called()

    def test_cidr_and_unsafe_credential_id_fail_closed(self):
        base = (
            "--scope", "192.0.2.0/24",
            "--engine", "postgresql",
            "--username", "audit-user",
            "--database-name", "postgres",
            "--password-env", "NIGHTRECON_DATABASE_PASSWORD",
            "--action", "database.server_identity",
        )
        code, _, stderr = self.run_cli(
            "infra", "database", "192.0.2.0/24",
            *base,
            "--credential-id", "database-readonly",
        )
        self.assertEqual(code, 2)
        self.assertIn("single host", stderr)

        code, _, stderr = self.run_cli(
            "infra", "database", "db01.example.test",
            "--scope", "db01.example.test",
            "--engine", "postgresql",
            "--username", "audit-user",
            "--database-name", "postgres",
            "--password-env", "NIGHTRECON_DATABASE_PASSWORD",
            "--action", "database.server_identity",
            "--credential-id", "unsafe credential!",
        )
        self.assertEqual(code, 2)
        self.assertIn("credential_id", stderr)

    def test_arbitrary_query_action_is_rejected_by_argparse(self):
        code, stdout, stderr = self.run_cli(
            "infra", "database", "db01.example.test",
            "--scope", "db01.example.test",
            "--engine", "postgresql",
            "--username", "audit-user",
            "--database-name", "postgres",
            "--credential-id", "database-readonly",
            "--password-env", "NIGHTRECON_DATABASE_PASSWORD",
            "--action", "database.run_query",
        )
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("invalid choice", stderr)


if __name__ == "__main__":
    unittest.main()
