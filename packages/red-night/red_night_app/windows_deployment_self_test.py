"""Local-only Windows deployment acceptance self-test.

This self-test deliberately performs no network activity and does not invoke
any Red assessment capability.  It validates frozen-package compatibility,
workspace persistence, professional report construction, and authenticated
encrypted backup/restore using a disposable temporary directory.
"""

from __future__ import annotations

import json
from pathlib import Path
import tempfile

from nightrecon_red_engine.engagement_report import (
    build_engagement_professional_report,
)
from nightrecon_red_engine.workspace_recovery import (
    create_encrypted_workspace_backup,
    restore_encrypted_workspace_backup,
    verify_encrypted_workspace_backup,
)
from nightrecon_shared_core.contracts import EngagementMetadata
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy
from nightrecon_shared_core.workspace import LocalWorkspace


ENGAGEMENT_ID = "windows-deployment-self-test"
TEST_TARGET = "192.0.2.10"
TEST_SCOPE = ("192.0.2.0/24",)
_TEST_PASSPHRASE = b"red-night-ci-local-backup-passphrase"


def run_windows_deployment_self_test() -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="red-night-windows-self-test-") as temp:
        root = Path(temp)
        workspace_root = root / "workspace"
        workspace = LocalWorkspace(workspace_root)
        workspace.create_engagement(EngagementMetadata(
            engagement_id=ENGAGEMENT_ID,
            name="Windows deployment self-test",
            created_at="2026-10-03T00:00:00+00:00",
            authorization_reference="self-test://local-only",
            status="active",
        ))
        workspace.set_execution_policy(EngagementExecutionPolicy(
            engagement_id=ENGAGEMENT_ID,
            scope=TEST_SCOPE,
            valid_from="2026-10-03T00:00:00+00:00",
            valid_until="2030-01-01T00:00:00+00:00",
            max_actions=2,
            permitted_capabilities=("discovery",),
        ))

        decision = workspace.authorize_action(
            ENGAGEMENT_ID,
            capability="discovery",
            target=TEST_TARGET,
            consume=True,
        )
        if not decision.allowed:
            raise AssertionError(f"local policy self-test was denied: {decision}")

        reopened = LocalWorkspace(workspace_root)
        summary = reopened.summary(ENGAGEMENT_ID)
        policy = reopened.execution_policy(ENGAGEMENT_ID)
        audit = reopened.authorization_audit(ENGAGEMENT_ID)
        if summary.status != "active" or policy.actions_used != 1 or len(audit) != 1:
            raise AssertionError("workspace state did not survive reopen")

        export_path = root / "engagement-export.json"
        reopened.export_file(ENGAGEMENT_ID, export_path)
        exported = json.loads(export_path.read_text(encoding="utf-8"))
        if exported["engagement_id"] != ENGAGEMENT_ID:
            raise AssertionError("workspace export did not preserve engagement identity")

        report = build_engagement_professional_report(
            reopened.envelope(ENGAGEMENT_ID)
        )
        report_path = root / "professional-report.json"
        report_path.write_text(
            json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        report_payload = json.loads(report_path.read_text(encoding="utf-8"))
        if report_payload["engagement_id"] != ENGAGEMENT_ID:
            raise AssertionError("professional report output is invalid")

        backup_path = root / "workspace.nrwb.enc"
        created = create_encrypted_workspace_backup(
            workspace_root,
            backup_path,
            passphrase=_TEST_PASSPHRASE,
        )
        verified = verify_encrypted_workspace_backup(
            backup_path,
            passphrase=_TEST_PASSPHRASE,
        )
        restored_root = root / "restored-workspace"
        restored = restore_encrypted_workspace_backup(
            backup_path,
            restored_root,
            passphrase=_TEST_PASSPHRASE,
        )
        if created != verified or verified != restored:
            raise AssertionError("encrypted backup verification/restore reports differ")

        restored_workspace = LocalWorkspace(restored_root)
        restored_summary = restored_workspace.summary(ENGAGEMENT_ID)
        restored_policy = restored_workspace.execution_policy(ENGAGEMENT_ID)
        restored_audit = restored_workspace.authorization_audit(ENGAGEMENT_ID)
        if (
            restored_summary.status != "active"
            or restored_policy.actions_used != 1
            or len(restored_audit) != 1
        ):
            raise AssertionError("restored workspace state is incomplete")

        return {
            "product": "Red Night",
            "test": "windows-deployment-self-test",
            "passed": True,
            "operational": False,
            "network_activity": False,
            "authorization_effect": "none",
            "workspace_reopen": True,
            "engagement_export": True,
            "professional_report": True,
            "encrypted_backup_verified": True,
            "encrypted_backup_restored": True,
            "restored_policy_actions_used": restored_policy.actions_used,
            "restored_audit_records": len(restored_audit),
        }
