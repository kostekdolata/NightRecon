"""Red Night v0.43 release acceptance for Controlled Validation Intelligence."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from nightrecon_red_engine.attack_path_atlas import build_cross_domain_attack_path_atlas
from nightrecon_red_engine.graph_builder import IdentityGraphBuilder
from nightrecon_red_engine.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
)
from nightrecon_red_engine.remediation_retest import RemediationStatus, RemediationStore
from nightrecon_red_engine.validation_adapter_contracts import bind_validation_eligibility_option
from nightrecon_red_engine.validation_attack_review import (
    BUILTIN_VALIDATION_ATTACK_REVIEW_REGISTRY,
    assert_attack_review_coverage,
)
from nightrecon_red_engine.validation_candidates import compile_validation_candidates
from nightrecon_red_engine.validation_comparison_lab import (
    ExpectedValidationScenario,
    ValidationComparisonExpectation,
    run_controlled_validation_fixture_comparison,
)
from nightrecon_red_engine.validation_evidence_lifecycle import (
    persist_validation_evidence_lifecycle,
    record_persisted_validation_retest,
)
from nightrecon_red_engine.validation_eligibility import plan_validation_eligibility
from nightrecon_red_engine.validation_worker import ValidationWorkerResult, ValidationWorkerState
from nightrecon_shared_core.contracts import EngagementMetadata
from nightrecon_shared_core.workspace import LocalWorkspace


NOW = datetime(2026, 9, 30, 0, 30, tzinfo=timezone.utc)
ENGAGEMENT = "eng-v043-release"


def provenance(key: str):
    return (GraphProvenance("engagement-evidence", key),)


def release_graph():
    identity = GraphNode.create(
        kind=GraphNodeKind.IDENTITY,
        natural_key="identity:v043-release",
        label="Release identity",
        provenance=provenance("identity"),
    )
    service = GraphNode.create(
        kind=GraphNodeKind.SERVICE,
        natural_key="192.0.2.43:443/tcp",
        label="Release HTTPS service",
        provenance=provenance("service"),
        properties=(("address", "192.0.2.43"), ("port", "443"), ("protocol", "tcp")),
    )
    critical = GraphNode.create(
        kind=GraphNodeKind.CRITICAL_ASSET,
        natural_key="critical:v043-release",
        label="Release critical asset",
        provenance=provenance("critical"),
    )
    edges = (
        GraphEdge.create(
            source_node_id=identity.node_id,
            target_node_id=service.node_id,
            relationship="correlates-to",
            evidence_state=GraphEvidenceState.INFERRED,
            provenance=provenance("edge-1"),
        ),
        GraphEdge.create(
            source_node_id=service.node_id,
            target_node_id=critical.node_id,
            relationship="evidence-path",
            evidence_state=GraphEvidenceState.OBSERVED,
            provenance=provenance("edge-2"),
        ),
    )
    builder = IdentityGraphBuilder()
    for node in (identity, service, critical):
        builder.add_node(node)
    for edge in edges:
        builder.add_edge(edge)
    return builder.build()


class V043ReleaseAcceptanceTests(unittest.TestCase):
    def test_full_reviewed_validation_chain_is_deterministic_and_bounded(self):
        graph = release_graph()
        atlas = build_cross_domain_attack_path_atlas(
            graph,
            start_kinds=(GraphNodeKind.IDENTITY,),
        )
        compilation = compile_validation_candidates(graph, atlas)
        self.assertEqual(len(compilation.candidates), 1)
        candidate = compilation.candidates[0]
        self.assertEqual(candidate.execution_mode, "proposal-only")
        self.assertEqual(candidate.required_capability, "validation.run")

        plan = plan_validation_eligibility(graph, compilation)
        option = next(
            item for item in plan.options
            if item.technique_id == "service.tcp-property-proof"
        )
        self.assertEqual(option.execution_mode, "proposal-only")

        binding = bind_validation_eligibility_option(graph, option)
        self.assertEqual(binding.execution_mode, "contract-only")
        self.assertEqual(binding.side_effect_mode, "none")
        self.assertEqual(binding.cleanup_mode, "none")
        self.assertEqual(binding.adapter_kind, "read-only-proof")

        result = ValidationWorkerResult(
            engagement_id=ENGAGEMENT,
            binding_id=binding.binding_id,
            technique_id=binding.technique_id,
            target="192.0.2.43",
            state=ValidationWorkerState.CONFIRMED,
            reason_code="validated",
            summary="Release fixture confirmed the selected TCP service.",
            evidence={"transport": "tcp", "port": 443, "state": "open"},
            limitations=("Deterministic release fixture; no live network action.",),
            actions_used=1,
            remaining_actions=1,
            worker_pid=4242,
        )

        with tempfile.TemporaryDirectory() as root:
            workspace = LocalWorkspace(root)
            workspace.create_engagement(EngagementMetadata(
                engagement_id=ENGAGEMENT,
                name="v0.43 release acceptance",
                created_at=NOW.isoformat(),
                authorization_reference="approval://v043-release",
                status="active",
            ))
            lifecycle = persist_validation_evidence_lifecycle(
                workspace,
                binding,
                result,
                observed_at=NOW,
            )
            self.assertEqual(lifecycle.added_records, 2)
            self.assertEqual(lifecycle.cleanup_state, "not-required")
            self.assertNotIn("4242", lifecycle.validation_record.to_json())

            remediation = RemediationStore(Path(root) / "remediation.json")
            remediation.create(
                engagement_id=ENGAGEMENT,
                finding_id="finding-v043-release",
                title="Release fixture finding",
                remediation="Apply the approved release-fixture remediation.",
                now=NOW,
            )
            remediation.transition("finding-v043-release", RemediationStatus.IN_PROGRESS, now=NOW)
            remediation.transition("finding-v043-release", RemediationStatus.READY_FOR_RETEST, now=NOW)
            outcome = record_persisted_validation_retest(
                workspace,
                remediation,
                "finding-v043-release",
                lifecycle,
                now=NOW,
            )
            self.assertTrue(outcome.conclusive)
            self.assertEqual(outcome.resulting_status, "regressed")
            finding = remediation.get("finding-v043-release")
            self.assertEqual(finding.last_validation_evidence_id, lifecycle.validation_evidence_id)
            self.assertEqual(finding.last_cleanup_evidence_id, lifecycle.cleanup_evidence_id)

        assert_attack_review_coverage()
        review = BUILTIN_VALIDATION_ATTACK_REVIEW_REGISTRY.get("service.tcp-property-proof")
        self.assertEqual(review.disposition, "related")
        self.assertEqual(review.attack_ids, ("T1046",))
        self.assertFalse(review.to_dict()["equivalence_claim"])

        comparison = run_controlled_validation_fixture_comparison(
            (lifecycle,),
            ValidationComparisonExpectation(
                scenarios=(
                    ExpectedValidationScenario(
                        "service.tcp-property-proof",
                        "confirmed",
                        ("port", "state", "transport"),
                        "not-required",
                        "related",
                        ("T1046",),
                    ),
                ),
                operator_steps=1,
            ),
        )
        self.assertEqual(comparison.matched_scenarios, 1)
        self.assertEqual(comparison.missed_scenarios, 0)
        self.assertEqual(comparison.invented_scenarios, 0)
        self.assertEqual(comparison.related_attack_scenarios, 1)
        self.assertEqual(len(comparison.comparison_sha256), 64)
        self.assertIn("do not establish", comparison.interpretation)


if __name__ == "__main__":
    unittest.main()
