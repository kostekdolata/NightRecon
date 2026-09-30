"""Build and verify the isolated White Night foundation distributions."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import venv
import zipfile


REPOSITORY = Path(__file__).resolve().parents[1]
WHITE_VERSION = "0.1.0a6"
SHARED_CORE_VERSION = "0.43.0"


def check(*args: str, cwd: Path) -> str:
    completed = subprocess.run(
        args,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if completed.returncode:
        raise AssertionError(
            f"Command {args[0]} failed ({completed.returncode}): "
            f"{completed.stdout[-1500:]} {completed.stderr[-1500:]}"
        )
    return completed.stdout


def scripts(directory: Path) -> tuple[Path, Path]:
    bin_dir = directory / ("Scripts" if os.name == "nt" else "bin")
    python = bin_dir / ("python.exe" if os.name == "nt" else "python")
    return bin_dir, python


def command(bin_dir: Path, name: str) -> str:
    return str(bin_dir / (name + (".exe" if os.name == "nt" else "")))


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="white-night-distribution-") as root:
        directory = Path(root)
        wheels = directory / "wheels"
        wheels.mkdir()

        for package in (
            REPOSITORY / "packages" / "shared-core",
            REPOSITORY / "packages" / "white-engine",
            REPOSITORY / "packages" / "white-night",
        ):
            check(
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-index",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                str(wheels),
                str(package),
                cwd=directory,
            )

        shared_core_wheel = next(
            wheels.glob(
                f"nightrecon_shared_core-{SHARED_CORE_VERSION}-*.whl"
            )
        )
        engine_wheel = next(
            wheels.glob(f"nightrecon_white_engine-{WHITE_VERSION}-*.whl")
        )
        app_wheel = next(
            wheels.glob(f"nightrecon_white_night-{WHITE_VERSION}-*.whl")
        )

        with zipfile.ZipFile(engine_wheel) as archive:
            engine_files = tuple(sorted(archive.namelist()))
        assert any(
            name.startswith("nightrecon_white_engine/") for name in engine_files
        )
        assert not any(
            name.startswith("nightrecon_red_engine/") for name in engine_files
        )
        assert not any(name.startswith("nightrecon/") for name in engine_files)

        with zipfile.ZipFile(app_wheel) as archive:
            app_files = tuple(sorted(archive.namelist()))
        assert any(name.startswith("white_night_app/") for name in app_files)
        assert not any(
            name.startswith("nightrecon_white_engine/") for name in app_files
        )
        assert not any(
            name.startswith("nightrecon_red_engine/") for name in app_files
        )
        assert not any(name.startswith("nightrecon/") for name in app_files)

        env_root = directory / "isolated"
        venv.create(env_root, with_pip=True)
        bin_dir, python = scripts(env_root)

        for wheel in (shared_core_wheel, engine_wheel, app_wheel):
            check(
                str(python),
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
                str(wheel),
                cwd=directory,
            )

        white_app = command(bin_dir, "white-night-app")
        help_text = check(white_app, "--help", cwd=directory)
        assert "White Night command boundary" in help_text
        assert "editions" in help_text
        assert "policy" in help_text
        assert "approval" in help_text
        assert "evidence" in help_text
        assert "audit" in help_text
        for forbidden in (
            "scan",
            "discover",
            "infra",
            "crawl",
            "identity",
            "workspace",
        ):
            assert forbidden not in help_text

        catalog = json.loads(
            check(white_app, "editions", "--json", cwd=directory)
        )
        assert len(catalog) == 5
        white = next(item for item in catalog if item["name"] == "White Night")
        assert white["standalone_available"] is False

        denied = subprocess.run(
            [white_app, "scan"],
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        assert denied.returncode == 2, denied
        assert "Traceback" not in denied.stderr

        check(
            str(python),
            "-c",
            (
                "import importlib.util; "
                "import nightrecon_shared_core as core; "
                "import nightrecon_white_engine as engine; "
                "assert core.edition_name('white') == 'White Night'; "
                "assert engine.WHITE_OWNED_COMMANDS == ('approval', 'audit', 'editions', 'evidence', 'policy'); "
                "assert engine.WHITE_ACTIVE_COMMANDS == (); "
                "assert importlib.util.find_spec('nightrecon') is None; "
                "assert importlib.util.find_spec('nightrecon_red_engine') is None"
            ),
            cwd=directory,
        )

        check(
            str(python),
            "-m",
            "white_night_app",
            "editions",
            "--json",
            cwd=directory,
        )

        check(
            str(python),
            "-c",
            (
                "from nightrecon_white_engine import "
                "DataHandlingPolicy, EngagementContact, EngagementDefinition, "
                "RulesOfEngagement, ScopeDefinition, render_rules_of_engagement; "
                "scope=ScopeDefinition(allowed=('192.0.2.0/24',), excluded=('192.0.2.250',)); "
                "roe=RulesOfEngagement("
                "engagement_id='eng-smoke', version=1, title='Packaged ROE', "
                "created_at='2026-09-29T12:00:00+00:00', "
                "valid_from='2026-10-01T08:00:00+00:00', "
                "valid_until='2026-10-02T18:00:00+00:00', scope=scope, "
                "allowed_techniques=('discovery',), max_actions=10, "
                "data_handling=DataHandlingPolicy()); "
                "contact=EngagementContact(contact_id='owner', display_name='Owner', role='lead'); "
                "eng=EngagementDefinition("
                "engagement_id='eng-smoke', version=1, name='Smoke', "
                "created_at='2026-09-29T12:00:00+00:00', status='planned', "
                "owner_contact_id='owner', contacts=(contact,), roe=roe); "
                "assert len(eng.fingerprint) == 64; "
                "assert 'does not itself authorize active operations' in render_rules_of_engagement(roe)"
            ),
            cwd=directory,
        )

        engagement_path = directory / "white-engagement.json"
        engagement_path.write_text(json.dumps({
            "schema_version": 1,
            "engagement_id": "eng-cli-smoke",
            "version": 1,
            "name": "CLI smoke",
            "created_at": "2026-09-29T12:00:00+00:00",
            "status": "planned",
            "owner_contact_id": "owner",
            "contacts": [{
                "contact_id": "owner",
                "display_name": "Owner",
                "role": "lead",
                "email": None,
                "phone": None,
            }],
            "roe": {
                "schema_version": 1,
                "engagement_id": "eng-cli-smoke",
                "version": 1,
                "title": "CLI smoke ROE",
                "created_at": "2026-09-29T12:00:00+00:00",
                "valid_from": "2026-10-01T08:00:00+00:00",
                "valid_until": "2026-10-02T18:00:00+00:00",
                "scope": {
                    "allowed": ["192.0.2.0/24"],
                    "excluded": ["192.0.2.250"],
                },
                "allowed_techniques": ["discovery"],
                "prohibited_techniques": [],
                "max_intrusiveness": "safe-active",
                "max_actions": 10,
                "data_handling": {
                    "classification": "confidential",
                    "retention_days": 90,
                    "export_allowed": True,
                    "notes": None,
                },
                "deviation_requires_approval": True,
                "notes": None,
            },
            "description": None,
        }, sort_keys=True), encoding="utf-8")
        bundle_path = directory / "compiled-policy.json"
        compiled = json.loads(check(
            white_app,
            "policy",
            "compile",
            str(engagement_path),
            "--output",
            str(bundle_path),
            cwd=directory,
        ))
        assert compiled["policy"]["max_impact"] == "standard"
        assert "192.0.2.250" not in compiled["policy"]["scope"]
        assert bundle_path.exists()
        verified = json.loads(check(
            white_app,
            "policy",
            "verify",
            str(bundle_path),
            cwd=directory,
        ))
        assert verified["integrity"] == "valid"
        assert verified["engagement_id"] == "eng-cli-smoke"

        approval_request_path = directory / "approval-request.json"
        approval_request_path.write_text(json.dumps({
            "schema_version": 1,
            "request_id": "approval-smoke",
            "engagement_id": "eng-cli-smoke",
            "policy_bundle_fingerprint": compiled["bundle_fingerprint"],
            "requested_at": "2026-09-29T16:00:00+00:00",
            "expires_at": "2026-09-29T18:00:00+00:00",
            "requested_by": "requester",
            "principals": [
                {
                    "principal_id": "requester",
                    "roles": ["operator"],
                },
                {
                    "principal_id": "approver",
                    "roles": ["approver"],
                },
            ],
            "capability": "discovery",
            "target": "192.0.2.10",
            "impact": "standard",
            "reason": "Approve isolated package smoke action",
            "policy": {
                "mode": "single",
                "required_approvals": 1,
                "eligible_roles": ["approver"],
                "requester_may_approve": False,
                "allow_delegation": True,
                "escalation_after_seconds": 600,
                "escalation_roles": ["approver"],
            },
            "operation_id": "operation-smoke",
        }, sort_keys=True), encoding="utf-8")

        workflow_pending = directory / "approval-pending.json"
        created = json.loads(check(
            white_app,
            "approval",
            "create",
            str(approval_request_path),
            "--event-id",
            "evt-requested",
            "--output",
            str(workflow_pending),
            cwd=directory,
        ))
        assert created["request"]["request_id"] == "approval-smoke"

        pending_status = json.loads(check(
            white_app,
            "approval",
            "status",
            str(workflow_pending),
            "--at",
            "2026-09-29T16:01:00+00:00",
            cwd=directory,
        ))
        assert pending_status["status"] == "pending"

        workflow_approved = directory / "approval-approved.json"
        approved = json.loads(check(
            white_app,
            "approval",
            "approve",
            str(workflow_pending),
            "--event-id",
            "evt-approved",
            "--actor-id",
            "approver",
            "--at",
            "2026-09-29T16:05:00+00:00",
            "--reason",
            "Approved for smoke validation",
            "--output",
            str(workflow_approved),
            cwd=directory,
        ))
        assert len(approved["events"]) == 2

        approval_status = json.loads(check(
            white_app,
            "approval",
            "status",
            str(workflow_approved),
            "--at",
            "2026-09-29T16:06:00+00:00",
            cwd=directory,
        ))
        assert approval_status["status"] == "approved"

        grant = json.loads(check(
            white_app,
            "approval",
            "grant",
            str(workflow_approved),
            "--at",
            "2026-09-29T16:06:00+00:00",
            cwd=directory,
        ))
        assert grant["request_id"] == "approval-smoke"
        assert grant["policy_bundle_fingerprint"] == compiled["bundle_fingerprint"]
        assert grant["capability"] == "discovery"
        assert grant["target"] == "192.0.2.10"

        approval_verified = json.loads(check(
            white_app,
            "approval",
            "verify",
            str(workflow_approved),
            cwd=directory,
        ))
        assert approval_verified["integrity"] == "valid"

        evidence_record_path = directory / "red-evidence.json"
        evidence_record_path.write_text(json.dumps({
            "schema_version": 1,
            "engagement_id": "eng-cli-smoke",
            "evidence_id": "ev-red-001",
            "source_night": "red",
            "evidence_type": "assessment.finding",
            "observed_at": "2026-09-29T16:10:00+00:00",
            "provenance": "isolated-smoke-fixture",
            "data": {
                "finding": "fixture-finding",
                "surface": "web",
            },
            "limitations": ["test fixture only"],
        }, sort_keys=True), encoding="utf-8")

        custody_initial = directory / "custody-initial.json"
        custody = json.loads(check(
            white_app,
            "evidence",
            "create",
            str(engagement_path),
            str(evidence_record_path),
            "--case-id",
            "case-smoke",
            "--event-id",
            "custody-ingest",
            "--actor-id",
            "collector",
            "--custodian-id",
            "custodian-a",
            "--at",
            "2026-09-29T16:20:00+00:00",
            "--reason",
            "Evidence intake for package smoke",
            "--output",
            str(custody_initial),
            cwd=directory,
        ))
        assert custody["authorization_effect"] == "none"
        assert custody["items"][0]["record"]["source_night"] == "red"
        assert custody["data_handling"]["classification"] == "confidential"

        custody_transferred = directory / "custody-transferred.json"
        transferred = json.loads(check(
            white_app,
            "evidence",
            "transfer",
            str(custody_initial),
            "--evidence-id",
            "ev-red-001",
            "--event-id",
            "custody-transfer",
            "--actor-id",
            "custodian-a",
            "--to-custodian",
            "custodian-b",
            "--at",
            "2026-09-29T16:25:00+00:00",
            "--reason",
            "Review handoff",
            "--output",
            str(custody_transferred),
            cwd=directory,
        ))
        assert transferred["events"][-1]["event_type"] == "transferred"

        manifest = json.loads(check(
            white_app,
            "evidence",
            "manifest",
            str(custody_transferred),
            "--at",
            "2026-09-29T16:26:00+00:00",
            cwd=directory,
        ))
        assert manifest["authorization_effect"] == "none"
        assert manifest["entries"][0]["evidence_id"] == "ev-red-001"
        assert "data" not in manifest["entries"][0]

        export_case = directory / "custody-exported.json"
        export_bundle = directory / "evidence-export.json"
        exported = json.loads(check(
            white_app,
            "evidence",
            "export",
            str(custody_transferred),
            "--event-id",
            "custody-export",
            "--actor-id",
            "custodian-b",
            "--destination",
            "offline-review",
            "--at",
            "2026-09-29T16:30:00+00:00",
            "--reason",
            "Approved package smoke export",
            "--case-output",
            str(export_case),
            "--output",
            str(export_bundle),
            cwd=directory,
        ))
        assert exported["authorization_effect"] == "none"
        assert exported["manifest"]["authorization_effect"] == "none"

        evidence_verified = json.loads(check(
            white_app,
            "evidence",
            "verify",
            str(export_bundle),
            cwd=directory,
        ))
        assert evidence_verified["integrity"] == "valid"
        assert evidence_verified["authorization_effect"] == "none"

        audit_initial = directory / "audit-initial.json"
        audit_created = json.loads(check(
            white_app,
            "audit",
            "create",
            "--trail-id",
            "audit-smoke",
            "--engagement-id",
            "eng-cli-smoke",
            "--event-id",
            "audit-ingest",
            "--event-type",
            "evidence.ingested",
            "--at",
            "2026-09-29T16:20:00+00:00",
            "--actor-id",
            "collector",
            "--subject-type",
            "evidence",
            "--subject-id",
            "ev-red-001",
            "--outcome",
            "success",
            "--reason-code",
            "evidence_ingested",
            "--summary",
            "Evidence entered custody",
            "--detail",
            "case_id=case-smoke",
            "--output",
            str(audit_initial),
            cwd=directory,
        ))
        assert len(audit_created["events"]) == 1

        audit_advanced = directory / "audit-advanced.json"
        audit_appended = json.loads(check(
            white_app,
            "audit",
            "append",
            str(audit_initial),
            "--event-id",
            "audit-export",
            "--event-type",
            "evidence.exported",
            "--at",
            "2026-09-29T16:30:00+00:00",
            "--actor-id",
            "custodian-b",
            "--subject-type",
            "custody.case",
            "--subject-id",
            "case-smoke",
            "--outcome",
            "success",
            "--reason-code",
            "evidence_exported",
            "--summary",
            "Governed evidence bundle exported",
            "--detail",
            "destination=offline-review",
            "--output",
            str(audit_advanced),
            cwd=directory,
        ))
        assert len(audit_appended["events"]) == 2

        audit_verified = json.loads(check(
            white_app,
            "audit",
            "verify",
            str(audit_advanced),
            cwd=directory,
        ))
        assert audit_verified["integrity"] == "valid"
        assert audit_verified["trail_id"] == "audit-smoke"

        metadata = check(
            str(python),
            "-c",
            (
                "import importlib.metadata as m; "
                "print(m.version('nightrecon-white-night')); "
                "print(m.version('nightrecon-white-engine')); "
                "print(m.version('nightrecon-shared-core')); "
                "print(m.requires('nightrecon-white-night'));"
            ),
            cwd=directory,
        )
        assert metadata.count(WHITE_VERSION) >= 2
        assert SHARED_CORE_VERSION in metadata
        assert "nightrecon-white-engine==0.1.0a6" in metadata
        assert "nightrecon-shared-core==0.43.0" in metadata
        assert "nightrecon-red" not in metadata
        assert "nightrecon==" not in metadata

        check(
            str(python),
            "-m",
            "pip",
            "uninstall",
            "--yes",
            "nightrecon-white-night",
            cwd=directory,
        )
        assert not Path(white_app).exists()
        check(
            str(python),
            "-c",
            (
                "import nightrecon_shared_core; "
                "import nightrecon_white_engine; "
                "assert nightrecon_shared_core is not None; "
                "assert nightrecon_white_engine is not None"
            ),
            cwd=directory,
        )

    print("White Night isolated distribution smoke: passed")


if __name__ == "__main__":
    main()
