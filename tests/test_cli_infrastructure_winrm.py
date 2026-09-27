"""CLI tests for bounded read-only WinRM infrastructure assessment."""

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
from nightrecon.infrastructure_models import (
    InfrastructureActionState,
)


_SECRET = "cli-winrm-secret-value"


class CliInfrastructureWinRmTests(unittest.TestCase):
    def run_cli(
        self,
        *args,
    ):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                *args,
            ],
        ):
            with contextlib.redirect_stdout(
                stdout
            ):
                with contextlib.redirect_stderr(
                    stderr
                ):
                    try:
                        main()
                        code = 0
                    except SystemExit as exc:
                        code = exc.code

        return (
            code,
            stdout.getvalue(),
            stderr.getvalue(),
        )

    def test_explicit_winrm_actions_are_reported_without_secret_or_source_name(self):
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
                    actions_used=(
                        state.actions_used + 1
                    ),
                    max_actions=state.max_actions,
                ),
                facts=(
                    InfrastructureFact(
                        key=(
                            "windows.hostname"
                            if action.action_id
                            == "winrm.system_identity"
                            else "windows.patch_count"
                        ),
                        value=(
                            "WIN01"
                            if action.action_id
                            == "winrm.system_identity"
                            else "3"
                        ),
                    ),
                ),
            )

        source_name = (
            "NIGHTRECON_WINRM_CLI_SECRET"
        )

        with patch.dict(
            os.environ,
            {
                source_name: _SECRET,
            },
            clear=False,
        ):
            with patch(
                "nightrecon.cli.execute_infrastructure_action",
                side_effect=fake_execute,
            ) as execute:
                with patch(
                    "nightrecon.cli.ResultStore"
                ) as store_class:
                    store_class.return_value.save_infrastructure_assessment_report.return_value = (
                        Path(
                            "results/session-infrastructure.json"
                        )
                    )

                    with patch(
                        "nightrecon.cli.NightReconLogger"
                    ) as logger_class:
                        code, stdout, stderr = self.run_cli(
                            "infra",
                            "winrm",
                            "win01.example.test",
                            "--scope",
                            "win01.example.test",
                            "--username",
                            "audit-user",
                            "--credential-id",
                            "corp-readonly",
                            "--password-env",
                            source_name,
                            "--action",
                            "winrm.system_identity",
                            "--action",
                            "winrm.patch_inventory",
                            "--max-actions",
                            "2",
                            "--max-patches",
                            "32",
                        )

        self.assertEqual(
            code,
            0,
        )
        self.assertEqual(
            stderr,
            "",
        )
        self.assertEqual(
            execute.call_count,
            2,
        )
        self.assertIn(
            "WinRM Assessment Summary: selected=2 attempted=2 successful=2 failed=0",
            stdout,
        )
        self.assertIn(
            "FACT windows.hostname=WIN01",
            stdout,
        )
        self.assertIn(
            "FACT windows.patch_count=3",
            stdout,
        )

        combined = (
            stdout
            + repr(
                logger_class.mock_calls
            )
        )
        self.assertNotIn(
            _SECRET,
            combined,
        )
        self.assertNotIn(
            source_name,
            combined,
        )

        saved_report = (
            store_class.return_value
            .save_infrastructure_assessment_report
            .call_args.args[0]
        )
        serialized_report = repr(
            saved_report.to_dict()
        )
        self.assertNotIn(
            _SECRET,
            serialized_report,
        )
        self.assertNotIn(
            source_name,
            serialized_report,
        )
        self.assertEqual(
            saved_report.transport,
            "winrm",
        )
        self.assertEqual(
            saved_report.authentication,
            "ntlm",
        )
        self.assertTrue(
            saved_report.tls_required
        )
        self.assertEqual(
            saved_report.certificate_validation,
            "required",
        )
        self.assertEqual(
            saved_report.max_patches,
            32,
        )

    def test_out_of_scope_target_fails_before_credential_resolution_or_execution(self):
        with patch(
            "nightrecon.cli.resolve_credential"
        ) as resolve:
            with patch(
                "nightrecon.cli.execute_infrastructure_action"
            ) as execute:
                with patch(
                    "nightrecon.cli.NightReconLogger"
                ):
                    code, stdout, stderr = self.run_cli(
                        "infra",
                        "winrm",
                        "outside.example.test",
                        "--scope",
                        "win01.example.test",
                        "--username",
                        "audit-user",
                        "--credential-id",
                        "corp-readonly",
                        "--password-env",
                        "NIGHTRECON_WINRM_PASSWORD",
                        "--action",
                        "winrm.system_identity",
                    )

        self.assertEqual(
            code,
            2,
        )
        self.assertEqual(
            stdout,
            "",
        )
        self.assertIn(
            "outside the authorized scope",
            stderr,
        )
        resolve.assert_not_called()
        execute.assert_not_called()

    def test_selected_actions_must_fit_budget_before_credential_resolution(self):
        with patch(
            "nightrecon.cli.resolve_credential"
        ) as resolve:
            with patch(
                "nightrecon.cli.execute_infrastructure_action"
            ) as execute:
                code, stdout, stderr = self.run_cli(
                    "infra",
                    "winrm",
                    "win01.example.test",
                    "--scope",
                    "win01.example.test",
                    "--username",
                    "audit-user",
                    "--credential-id",
                    "corp-readonly",
                    "--password-env",
                    "NIGHTRECON_WINRM_PASSWORD",
                    "--action",
                    "winrm.system_identity",
                    "--action",
                    "winrm.patch_inventory",
                    "--max-actions",
                    "1",
                )

        self.assertEqual(
            code,
            2,
        )
        self.assertEqual(
            stdout,
            "",
        )
        self.assertIn(
            "exceed max_actions",
            stderr,
        )
        resolve.assert_not_called()
        execute.assert_not_called()

    def test_missing_password_environment_source_fails_generically(self):
        source_name = (
            "NIGHTRECON_MISSING_WINRM_PASSWORD"
        )

        with patch.dict(
            os.environ,
            {},
            clear=True,
        ):
            with patch(
                "nightrecon.cli.execute_infrastructure_action"
            ) as execute:
                with patch(
                    "nightrecon.cli.NightReconLogger"
                ):
                    code, stdout, stderr = self.run_cli(
                        "infra",
                        "winrm",
                        "win01.example.test",
                        "--scope",
                        "win01.example.test",
                        "--username",
                        "audit-user",
                        "--credential-id",
                        "corp-readonly",
                        "--password-env",
                        source_name,
                        "--action",
                        "winrm.system_identity",
                    )

        self.assertEqual(
            code,
            2,
        )
        self.assertEqual(
            stdout,
            "",
        )
        self.assertIn(
            "WinRM credential could not be resolved",
            stderr,
        )
        self.assertNotIn(
            source_name,
            stderr,
        )
        execute.assert_not_called()

    def test_arbitrary_winrm_action_is_rejected_by_argparse(self):
        with patch(
            "nightrecon.cli.execute_infrastructure_action"
        ) as execute:
            code, stdout, stderr = self.run_cli(
                "infra",
                "winrm",
                "win01.example.test",
                "--scope",
                "win01.example.test",
                "--username",
                "audit-user",
                "--credential-id",
                "corp-readonly",
                "--password-env",
                "NIGHTRECON_WINRM_PASSWORD",
                "--action",
                "winrm.run_powershell",
            )

        self.assertEqual(
            code,
            2,
        )
        self.assertEqual(
            stdout,
            "",
        )
        self.assertIn(
            "invalid choice",
            stderr,
        )
        execute.assert_not_called()

    def test_cidr_target_and_unsafe_credential_id_are_rejected(self):
        base = (
            "infra",
            "winrm",
            "10.0.0.0/24",
            "--scope",
            "10.0.0.0/24",
            "--username",
            "audit-user",
            "--credential-id",
            "corp-readonly",
            "--password-env",
            "NIGHTRECON_WINRM_PASSWORD",
            "--action",
            "winrm.system_identity",
        )

        code, stdout, stderr = self.run_cli(
            *base
        )

        self.assertEqual(
            code,
            2,
        )
        self.assertEqual(
            stdout,
            "",
        )
        self.assertIn(
            "single host or IP",
            stderr,
        )

        args = list(
            base
        )
        args[2] = (
            "win01.example.test"
        )
        args[4] = (
            "win01.example.test"
        )
        credential_index = (
            args.index(
                "--credential-id"
            )
            + 1
        )
        args[
            credential_index
        ] = "bad id\n"

        code, stdout, stderr = self.run_cli(
            *args
        )

        self.assertEqual(
            code,
            2,
        )
        self.assertIn(
            "credential_id must contain only",
            stderr,
        )


if __name__ == "__main__":
    unittest.main()
