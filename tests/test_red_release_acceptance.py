"""Stack-wide Red Night v0.40 release acceptance.

The scenario is deterministic and network-free. Provider and validation adapters
are fakes, while every policy, persistence, evidence, graph, planning,
remediation, and ecosystem boundary under test is the production implementation.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest

from nightrecon_red_engine.assessment_engine import CheckIntrusiveness
from nightrecon_red_engine.autonomous_operator import (
    OperatorContext,
    OperatorProposal,
    compile_autonomous_plan,
)
from nightrecon_red_engine.check_ecosystem import (
    CheckEcosystemPolicy,
    EcosystemPackProvenance,
    VerifiedEcosystemPack,
    build_check_catalog,
)
from nightrecon_red_engine.check_packs import load_check_pack_payload
from nightrecon_red_engine.cloud_hybrid_intelligence import (
    CloudCollectionRequest,
    collect_authorized_cloud_intelligence,
)
from nightrecon_red_engine.controlled_validation import (
    ValidationDefinition,
    ValidationObservation,
    ValidationState,
    run_controlled_validation,
)
from nightrecon_red_engine.identity_collection import (
    DirectoryEntry,
    IdentityCollectionRequest,
    collect_authorized_identity_intelligence,
)
from nightrecon_red_engine.identity_engagement_evidence import (
    identity_bundle_to_engagement_records,
)
from nightrecon_red_engine.remediation_retest import (
    RemediationStatus,
    RemediationStore,
)
from nightrecon_red_engine.unified_attack_graph import build_unified_attack_graph
from nightrecon_shared_core.contracts import (
    EngagementEnvelope,
    EngagementMetadata,
    EvidenceRecord,
)
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy
from nightrecon_shared_core.workspace import LocalWorkspace


NOW = datetime(2026, 9, 28, 12, 0, tzinfo=timezone.utc)
OBSERVED_AT = NOW.isoformat()
ENGAGEMENT_ID = "eng-release-acceptance"


class IdentityProvider:
    def __init__(self):
        self.calls = 0

    def collect(self, request):
        self.calls += 1
        return (
            DirectoryEntry("CN=Alice,DC=example,DC=test", "user", "Alice"),
            DirectoryEntry(
                "CN=Ops,DC=example,DC=test", "group", "Ops",
                ("CN=Alice,DC=example,DC=test",),
            ),
        )


class CloudProvider:
    def __init__(self):
        self.calls = 0

    def collect_normalized_snapshot(self, request):
        self.calls += 1
        return json.dumps({
            "schema_version": 1,
            "resources": [
                {
                    "provider": "azure",
                    "id": "vm-1",
                    "kind": "virtual-machine",
                    "name": "Finance VM",
                },
            ],
            "identities": [
                {"provider": "entra", "id": "alice", "name": "Alice Cloud"},
            ],
            "relationships": [
                {
                    "source_type": "identity",
                    "source_provider": "entra",
                    "source_id": "alice",
                    "target_type": "resource",
                    "target_provider": "azure",
                    "target_id": "vm-1",
                    "relationship": "owner",
                },
            ],
        }, separators=(",", ":")).encode()


class ValidationAdapter:
    def __init__(self, confirmed):
        self.confirmed = confirmed
        self.calls = 0

    def execute(self, definition):
        self.calls += 1
        return ValidationObservation(
            confirmed=self.confirmed,
            summary=(
                "Expected condition remains observable."
                if self.confirmed else
                "Expected condition is no longer observable."
            ),
            evidence={"target": definition.target, "proof": "read-only"},
            limitations=("Deterministic read-only acceptance proof.",),
        )


class PlanningAgent:
    def propose(self, context):
        return (
            OperatorProposal("discovery", "192.0.2.10", "Refresh approved asset evidence."),
            OperatorProposal(
                "validation.run", "192.0.2.10", "Retest confirmed finding.",
                approval_present=True,
            ),
            OperatorProposal("scan", "198.51.100.10", "Outside-scope proposal."),
        )


def make_workspace(root):
    workspace = LocalWorkspace(root)
    workspace.create_engagement(EngagementMetadata(
        engagement_id=ENGAGEMENT_ID,
        name="v0.40 release acceptance",
        created_at="2026-09-28T00:00:00+00:00",
        authorization_reference="approval://release-acceptance",
        status="active",
    ))
    workspace.set_execution_policy(EngagementExecutionPolicy(
        engagement_id=ENGAGEMENT_ID,
        scope=("192.0.2.0/24", "dc.example.test", "management.example.test"),
        valid_from="2026-09-28T00:00:00+00:00",
        valid_until="2026-09-29T00:00:00+00:00",
        max_actions=8,
        permitted_capabilities=(
            "cloud.collect",
            "discovery",
            "identity.collect",
            "scan",
            "validation.run",
        ),
        approval_required_capabilities=("validation.run",),
    ))
    return workspace


def append_records(workspace, records):
    report = workspace.merge_envelope(EngagementEnvelope(
        engagement_id=ENGAGEMENT_ID,
        records=tuple(records),
    ))
    if not report.applied:
        raise AssertionError("acceptance evidence merge unexpectedly failed")


def fixture_record(evidence_id, evidence_type, data):
    return EvidenceRecord(
        engagement_id=ENGAGEMENT_ID,
        evidence_id=evidence_id,
        source_night="red",
        evidence_type=evidence_type,
        observed_at=OBSERVED_AT,
        provenance=f"acceptance://{evidence_id}",
        data=data,
        limitations=("Release-acceptance fixture evidence.",),
    )


def verified_check_pack():
    pack = load_check_pack_payload({
        "schema_version": 1,
        "pack_id": "acceptance.tls",
        "name": "Acceptance TLS",
        "version": "1.0.0",
        "checks": [{
            "check_id": "acceptance.tls.present",
            "name": "TLS evidence present",
            "family": "tls",
            "description": "Declarative acceptance fixture.",
            "intrusiveness": "safe-active",
            "supported_services": ["https"],
            "tags": ["release-acceptance"],
            "conditions": [{"field": "tls_version", "operator": "present"}],
            "finding": {"title": "TLS finding", "summary": "Acceptance finding."},
            "evidence_fields": ["tls_version"],
            "required_capabilities": ["validation.run"],
        }],
    })
    return VerifiedEcosystemPack(
        pack,
        EcosystemPackProvenance(
            signer_key_id="release-trusted-key",
            source_feed_id="release-feed",
            sha256="a" * 64,
        ),
    )


class RedReleaseAcceptanceTests(unittest.TestCase):
    def test_complete_engagement_workflow_is_coherent_and_persistent(self):
        with tempfile.TemporaryDirectory(prefix="red-release-acceptance-") as root:
            workspace = make_workspace(root)

            # Existing discovery evidence anchors validation/remediation to a real asset.
            append_records(workspace, (
                fixture_record("asset-local", "asset.observation", {
                    "asset_key": "192.0.2.10",
                    "label": "Finance Application",
                }),
            ))

            identity_provider = IdentityProvider()
            identity = collect_authorized_identity_intelligence(
                workspace,
                identity_provider,
                IdentityCollectionRequest(
                    engagement_id=ENGAGEMENT_ID,
                    source_id="ad-readonly",
                    source_type="active-directory",
                    target="dc.example.test",
                ),
                now=NOW,
            )
            self.assertEqual(identity_provider.calls, 1)
            identity_records = identity_bundle_to_engagement_records(
                identity.evidence,
                engagement_id=ENGAGEMENT_ID,
                observed_at=OBSERVED_AT,
            )
            append_records(workspace, identity_records)

            cloud_provider = CloudProvider()
            cloud = collect_authorized_cloud_intelligence(
                workspace,
                cloud_provider,
                CloudCollectionRequest(
                    engagement_id=ENGAGEMENT_ID,
                    source_id="cloud-readonly",
                    target="management.example.test",
                ),
                now=NOW,
            )
            self.assertEqual(cloud_provider.calls, 1)
            append_records(workspace, cloud.records)

            proof_adapter = ValidationAdapter(True)
            proof = run_controlled_validation(
                workspace,
                proof_adapter,
                ValidationDefinition(
                    "finance-readonly-proof",
                    "192.0.2.10",
                    "Validate observed finance condition",
                    requires_approval=True,
                ),
                engagement_id=ENGAGEMENT_ID,
                approval_present=True,
                now=NOW,
            )
            self.assertIs(proof.state, ValidationState.CONFIRMED)
            self.assertEqual(proof_adapter.calls, 1)

            append_records(workspace, (
                fixture_record("finding-finance", "assessment.finding", {
                    "target_kind": "asset",
                    "target_key": "192.0.2.10",
                    "finding_key": "finding-finance",
                    "label": "Validated finance condition",
                }),
                fixture_record("critical-finance", "critical-asset.observation", {
                    "asset_key": "192.0.2.10",
                    "critical_key": "finance-app",
                    "label": "Finance Application",
                }),
            ))

            graph = build_unified_attack_graph(
                workspace.envelope(ENGAGEMENT_ID).records
            )
            self.assertEqual(graph.unresolved_records, ())
            relationships = {edge.relationship for edge in graph.graph.edges}
            self.assertTrue({
                "member-of", "owner", "has-finding", "represents-critical-asset",
            }.issubset(relationships))

            actions_before_plan = LocalWorkspace(root).execution_policy(
                ENGAGEMENT_ID
            ).actions_used
            plan = compile_autonomous_plan(
                LocalWorkspace(root),
                PlanningAgent(),
                OperatorContext(
                    ENGAGEMENT_ID,
                    "Review the validated path and prepare a bounded retest plan.",
                ),
                now=NOW,
            )
            self.assertEqual(
                tuple(step.status for step in plan.steps),
                ("allowed", "allowed", "blocked"),
            )
            self.assertEqual(plan.steps[-1].reason_code, "target_out_of_scope")
            self.assertEqual(plan.execution_mode, "plan-only")
            self.assertEqual(
                LocalWorkspace(root).execution_policy(ENGAGEMENT_ID).actions_used,
                actions_before_plan,
            )

            catalog = build_check_catalog(
                (verified_check_pack(),),
                CheckEcosystemPolicy(
                    trusted_signers=("release-trusted-key",),
                    max_intrusiveness=CheckIntrusiveness.SAFE_ACTIVE,
                    allowed_capabilities=("validation.run",),
                ),
            )
            self.assertEqual(len(catalog.entries), 1)
            self.assertTrue(catalog.entries[0].eligible)

            remediation_path = Path(root) / "remediation.json"
            remediation = RemediationStore(remediation_path)
            remediation.create(
                engagement_id=ENGAGEMENT_ID,
                finding_id="finding-finance",
                title="Validated finance condition",
                remediation="Apply the approved configuration correction.",
                now=NOW,
            )
            remediation.transition(
                "finding-finance", RemediationStatus.IN_PROGRESS
            )
            remediation.transition(
                "finding-finance", RemediationStatus.READY_FOR_RETEST
            )

            retest_adapter = ValidationAdapter(False)
            retest = run_controlled_validation(
                LocalWorkspace(root),
                retest_adapter,
                ValidationDefinition(
                    "finance-readonly-retest",
                    "192.0.2.10",
                    "Retest remediated finance condition",
                    requires_approval=True,
                ),
                engagement_id=ENGAGEMENT_ID,
                approval_present=True,
                now=NOW,
            )
            self.assertIs(retest.state, ValidationState.NOT_CONFIRMED)
            outcome = remediation.record_retest("finding-finance", retest)
            self.assertTrue(outcome.conclusive)
            self.assertEqual(outcome.resulting_status, "verified")

            reopened = LocalWorkspace(root)
            self.assertEqual(
                reopened.execution_policy(ENGAGEMENT_ID).actions_used, 4
            )
            self.assertEqual(
                RemediationStore(remediation_path).get("finding-finance").status,
                RemediationStatus.VERIFIED,
            )
            self.assertGreater(len(reopened.authorization_audit(ENGAGEMENT_ID)), 4)
            rebuilt = build_unified_attack_graph(
                reopened.envelope(ENGAGEMENT_ID).records
            )
            self.assertEqual(rebuilt.graph, graph.graph)


if __name__ == "__main__":
    unittest.main()
