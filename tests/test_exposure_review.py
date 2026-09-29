"""Exposure review reports gaps and structural counts without scoring risk."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from nightrecon_red_engine.attack_path_atlas import (
    build_cross_domain_attack_path_atlas,
)
from nightrecon_red_engine.exposure_review import (
    build_exposure_review,
    compare_path_sets,
)
from nightrecon_red_engine.graph_builder import IdentityGraphBuilder
from nightrecon_red_engine.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
)
from nightrecon_red_engine.remediation_retest import (
    RemediationStatus,
    RemediationStore,
)
from nightrecon_red_engine.validation_candidates import (
    compile_validation_candidates,
)


def prov(key):
    return (GraphProvenance("engagement-evidence", key),)


def build_fixture(include_critical_edge=True):
    identity = GraphNode.create(
        kind=GraphNodeKind.IDENTITY,
        natural_key="identity:alice",
        label="Alice",
        provenance=prov("identity"),
    )
    asset = GraphNode.create(
        kind=GraphNodeKind.ASSET,
        natural_key="192.0.2.20",
        label="App",
        provenance=prov("asset"),
    )
    critical = GraphNode.create(
        kind=GraphNodeKind.CRITICAL_ASSET,
        natural_key="critical:finance",
        label="Finance",
        provenance=prov("critical"),
    )
    builder = IdentityGraphBuilder()
    for item in (identity, asset, critical):
        builder.add_node(item)
    builder.add_edge(GraphEdge.create(
        source_node_id=identity.node_id,
        target_node_id=asset.node_id,
        relationship="correlates-to",
        evidence_state=GraphEvidenceState.INFERRED,
        provenance=prov("corr"),
    ))
    if include_critical_edge:
        builder.add_edge(GraphEdge.create(
            source_node_id=asset.node_id,
            target_node_id=critical.node_id,
            relationship="classified-as-critical",
            evidence_state=GraphEvidenceState.OBSERVED,
            provenance=prov("critical-link"),
        ))
    graph = builder.build()
    atlas = build_cross_domain_attack_path_atlas(
        graph,
        start_kinds=(GraphNodeKind.IDENTITY,),
    )
    return graph, atlas


class ExposureReviewTests(unittest.TestCase):
    def test_review_surfaces_inferred_gap_retest_and_concentration(self):
        graph, atlas = build_fixture()
        compilation = compile_validation_candidates(graph, atlas)

        with tempfile.TemporaryDirectory() as root:
            store = RemediationStore(Path(root) / "remediation.json")
            store.create(
                engagement_id="eng",
                finding_id="finding-1",
                title="Finding",
                remediation="Apply fix.",
                now=datetime(2026, 9, 29, 12, tzinfo=timezone.utc),
            )
            store.transition(
                "finding-1",
                RemediationStatus.IN_PROGRESS,
            )
            store.transition(
                "finding-1",
                RemediationStatus.READY_FOR_RETEST,
            )
            review = build_exposure_review(
                atlas,
                compilation,
                remediation_findings=store.list("eng"),
            )

        self.assertEqual(len(review.paths), 1)
        self.assertEqual(
            review.paths[0].candidate_id,
            compilation.candidates[0].candidate_id,
        )
        self.assertTrue(any(
            item.gap_type == "inferred-path-evidence"
            for item in review.evidence_gaps
        ))
        self.assertTrue(any(
            item.gap_type == "retest-state"
            for item in review.evidence_gaps
        ))
        self.assertEqual(
            dict(review.remediation_status_counts)["ready-for-retest"],
            1,
        )
        self.assertNotIn("risk_score", str(review.to_dict()).lower())
        self.assertIn("not risk scores", review.interpretation)

    def test_path_set_change_is_descriptive(self):
        _, before = build_fixture(True)
        _, after = build_fixture(False)
        change = compare_path_sets(before, after)
        self.assertEqual(change.before_count, 1)
        self.assertEqual(change.after_count, 0)
        self.assertEqual(len(change.removed_path_ids), 1)
        self.assertIn("does not by itself prove", change.interpretation)


if __name__ == "__main__":
    unittest.main()
