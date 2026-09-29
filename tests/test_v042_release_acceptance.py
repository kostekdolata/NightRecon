"""Red Night v0.42 release acceptance for exposure intelligence."""

from __future__ import annotations

import unittest

from nightrecon_red_engine.attack_path_atlas import (
    build_cross_domain_attack_path_atlas,
)
from nightrecon_red_engine.exposure_review import build_exposure_review
from nightrecon_red_engine.graph_models import GraphNodeKind
from nightrecon_red_engine.specialist_comparison import (
    ExpectedEdgeSignature,
    ExpectedPathSignature,
    SpecialistComparisonExpectation,
    run_specialist_fixture_comparison,
)
from nightrecon_red_engine.unified_attack_graph import (
    build_correlated_unified_attack_graph,
)
from nightrecon_red_engine.validation_candidates import (
    compile_validation_candidates,
)
from nightrecon_shared_core.contracts import EvidenceRecord


ENGAGEMENT = "eng-v042-release"
OBSERVED_AT = "2026-09-29T15:00:00+00:00"
CLOUD_KEY = "cloud:azure:resource:release-vm"


def record(evidence_id, evidence_type, data):
    return EvidenceRecord(
        engagement_id=ENGAGEMENT,
        evidence_id=evidence_id,
        source_night="red",
        evidence_type=evidence_type,
        observed_at=OBSERVED_AT,
        provenance=f"release://{evidence_id}",
        data=data,
        limitations=("Deterministic v0.42 release-acceptance fixture.",),
    )


class V042ReleaseAcceptanceTests(unittest.TestCase):
    def test_cross_domain_release_chain_is_exact_bounded_and_proposal_only(self):
        records = (
            record("network", "asset.observation", {
                "asset_key": "192.0.2.42",
                "label": "Observed application host",
                "properties": {
                    "address": "192.0.2.42",
                    "hostnames": "app42.example.test",
                },
            }),
            record("identity", "identity.observation", {
                "identity_key": "ad:computer:release",
                "label": "APP42",
                "properties": {
                    "dns_hostname": "app42.example.test",
                    "identity_type": "ad-computer",
                },
            }),
            record("cloud", "asset.observation", {
                "asset_key": CLOUD_KEY,
                "label": "Azure application VM",
                "properties": {
                    "cloud_provider": "azure",
                    "cloud_resource_id": "release-vm",
                    "cloud_resource_kind": "virtual-machine",
                    "private_ip": "192.0.2.42",
                },
            }),
            record("critical", "critical-asset.observation", {
                "asset_key": CLOUD_KEY,
                "critical_key": "critical:release-finance",
                "label": "Finance system",
            }),
        )

        correlated = build_correlated_unified_attack_graph(records)
        self.assertEqual(correlated.unresolved_records, ())
        self.assertEqual(correlated.unresolved_correlations, ())
        self.assertEqual(len(correlated.correlated_edge_ids), 2)

        atlas = build_cross_domain_attack_path_atlas(
            correlated.graph,
            start_kinds=(GraphNodeKind.IDENTITY,),
        )
        self.assertEqual(len(atlas.paths), 1)
        self.assertEqual(atlas.paths[0].observed_hops, 1)
        self.assertEqual(atlas.paths[0].inferred_hops, 2)
        self.assertFalse(atlas.truncated)

        compilation = compile_validation_candidates(correlated.graph, atlas)
        self.assertEqual(len(compilation.candidates), 1)
        candidate = compilation.candidates[0]
        self.assertEqual(candidate.execution_mode, "proposal-only")
        self.assertTrue(candidate.approval_required)
        self.assertTrue(candidate.scope_review_required)

        review = build_exposure_review(
            atlas,
            compilation,
            unresolved_correlations=correlated.unresolved_correlations,
        )
        self.assertTrue(any(
            item.gap_type == "inferred-path-evidence"
            for item in review.evidence_gaps
        ))
        self.assertNotIn("risk_score", str(review.to_dict()).lower())

        comparison = run_specialist_fixture_comparison(
            correlated.graph,
            SpecialistComparisonExpectation(
                paths=(
                    ExpectedPathSignature(
                        "ad:computer:release",
                        "critical:release-finance",
                        (
                            "correlates-to",
                            "correlates-to",
                            "represents-critical-asset",
                        ),
                    ),
                ),
                edges=(
                    ExpectedEdgeSignature(
                        "ad:computer:release",
                        "192.0.2.42",
                        "correlates-to",
                        "inferred",
                    ),
                    ExpectedEdgeSignature(
                        "192.0.2.42",
                        CLOUD_KEY,
                        "correlates-to",
                        "inferred",
                    ),
                    ExpectedEdgeSignature(
                        CLOUD_KEY,
                        "critical:release-finance",
                        "represents-critical-asset",
                        "observed",
                    ),
                ),
                operator_steps=4,
            ),
            start_kinds=(GraphNodeKind.IDENTITY,),
        )
        self.assertEqual(comparison.missed_paths, 0)
        self.assertEqual(comparison.invented_paths, 0)
        self.assertEqual(comparison.missed_edges, 0)
        self.assertEqual(comparison.invented_edges, 0)
        self.assertEqual(comparison.evidence_incomplete_paths, 0)
        self.assertFalse(comparison.atlas_truncated)


if __name__ == "__main__":
    unittest.main()
