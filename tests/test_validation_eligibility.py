"""v0.43 Batch 2 exact candidate-to-technique eligibility tests."""

from __future__ import annotations

from dataclasses import replace
import unittest

from nightrecon_red_engine.attack_path_atlas import (
    build_cross_domain_attack_path_atlas,
)
from nightrecon_red_engine.graph_builder import IdentityGraphBuilder
from nightrecon_red_engine.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
)
from nightrecon_red_engine.validation_candidates import (
    compile_validation_candidates,
)
from nightrecon_red_engine.validation_eligibility import (
    ValidationEligibilityLimits,
    plan_validation_eligibility,
)


def provenance(key):
    return (GraphProvenance("engagement-evidence", key),)


def service_fixture(*, tls=True):
    identity = GraphNode.create(
        kind=GraphNodeKind.IDENTITY,
        natural_key="identity:alice",
        label="Alice",
        provenance=provenance("identity"),
    )
    properties = [
        ("address", "192.0.2.43"),
        ("port", "443"),
        ("protocol", "tcp"),
    ]
    if tls:
        properties.append(("tls_certificate_sha256", "abc123"))
    service = GraphNode.create(
        kind=GraphNodeKind.SERVICE,
        natural_key="192.0.2.43:443/tcp",
        label="https",
        provenance=provenance("service"),
        properties=tuple(properties),
    )
    critical = GraphNode.create(
        kind=GraphNodeKind.CRITICAL_ASSET,
        natural_key="critical:finance",
        label="Finance",
        provenance=provenance("critical"),
    )
    first = GraphEdge.create(
        source_node_id=identity.node_id,
        target_node_id=service.node_id,
        relationship="correlates-to",
        evidence_state=GraphEvidenceState.INFERRED,
        provenance=provenance("edge-1"),
    )
    second = GraphEdge.create(
        source_node_id=service.node_id,
        target_node_id=critical.node_id,
        relationship="evidence-path",
        evidence_state=GraphEvidenceState.OBSERVED,
        provenance=provenance("edge-2"),
    )
    builder = IdentityGraphBuilder()
    for node in (identity, service, critical):
        builder.add_node(node)
    for edge in (first, second):
        builder.add_edge(edge)
    graph = builder.build()
    atlas = build_cross_domain_attack_path_atlas(
        graph,
        start_kinds=(GraphNodeKind.IDENTITY,),
    )
    return graph, compile_validation_candidates(graph, atlas), service


def web_fixture():
    identity = GraphNode.create(
        kind=GraphNodeKind.IDENTITY,
        natural_key="identity:bob",
        label="Bob",
        provenance=provenance("identity-web"),
    )
    web = GraphNode.create(
        kind=GraphNodeKind.SERVICE,
        natural_key="web-surface:web:opaque",
        label="https://app.example.test",
        provenance=provenance("web-surface"),
        properties=(
            ("origin_host", "app.example.test"),
            ("origin_port", "443"),
            ("origin_scheme", "https"),
            ("surface_type", "web"),
        ),
    )
    critical = GraphNode.create(
        kind=GraphNodeKind.CRITICAL_ASSET,
        natural_key="critical:web-app",
        label="Critical web app",
        provenance=provenance("critical-web"),
    )
    first = GraphEdge.create(
        source_node_id=identity.node_id,
        target_node_id=web.node_id,
        relationship="correlates-to",
        evidence_state=GraphEvidenceState.INFERRED,
        provenance=provenance("web-edge-1"),
    )
    second = GraphEdge.create(
        source_node_id=web.node_id,
        target_node_id=critical.node_id,
        relationship="evidence-path",
        evidence_state=GraphEvidenceState.OBSERVED,
        provenance=provenance("web-edge-2"),
    )
    builder = IdentityGraphBuilder()
    for node in (identity, web, critical):
        builder.add_node(node)
    for edge in (first, second):
        builder.add_edge(edge)
    graph = builder.build()
    atlas = build_cross_domain_attack_path_atlas(
        graph,
        start_kinds=(GraphNodeKind.IDENTITY,),
    )
    return graph, compile_validation_candidates(graph, atlas), web


class ValidationEligibilityTests(unittest.TestCase):
    def test_exact_service_evidence_exposes_all_matching_review_options(self):
        graph, compilation, service = service_fixture(tls=True)

        plan = plan_validation_eligibility(graph, compilation)

        self.assertEqual(
            tuple(item.technique_id for item in plan.options),
            (
                "service.tcp-property-proof",
                "service.tls-property-proof",
            ),
        )
        self.assertTrue(all(
            item.target_node_id == service.node_id
            for item in plan.options
        ))
        self.assertTrue(all(
            item.execution_mode == "proposal-only"
            for item in plan.options
        ))
        self.assertEqual(
            {item.technique_id for item in plan.rejections},
            {"web.http-policy-proof"},
        )

    def test_missing_tls_prerequisite_does_not_block_tcp_option(self):
        graph, compilation, _service = service_fixture(tls=False)

        plan = plan_validation_eligibility(graph, compilation)

        self.assertEqual(
            tuple(item.technique_id for item in plan.options),
            ("service.tcp-property-proof",),
        )
        tls_rejection = next(
            item for item in plan.rejections
            if item.technique_id == "service.tls-property-proof"
        )
        self.assertEqual(
            tls_rejection.reason,
            "target-evidence-prerequisites-not-satisfied",
        )
        self.assertEqual(tls_rejection.compatible_target_count, 1)

    def test_expected_output_evidence_is_not_treated_as_preexisting_evidence(self):
        graph, compilation, web = web_fixture()

        plan = plan_validation_eligibility(graph, compilation)

        option = next(
            item for item in plan.options
            if item.technique_id == "web.http-policy-proof"
        )
        self.assertEqual(option.target_kind, "web")
        self.assertEqual(option.target_node_id, web.node_id)
        self.assertEqual(
            option.expected_evidence_keys,
            ("status_code", "security_headers"),
        )
        self.assertNotIn("status_code", dict(web.properties))
        self.assertNotIn("security_headers", dict(web.properties))

    def test_tampered_candidate_evidence_fails_closed(self):
        graph, compilation, _service = service_fixture()
        candidate = compilation.candidates[0]
        tampered = replace(
            compilation,
            candidates=(
                replace(candidate, evidence_ids=("invented-evidence",)),
            ),
        )

        with self.assertRaisesRegex(ValueError, "evidence identifiers"):
            plan_validation_eligibility(graph, tampered)

    def test_planner_is_deterministic_and_does_not_select_one_option(self):
        graph, compilation, _service = service_fixture()

        first = plan_validation_eligibility(graph, compilation)
        second = plan_validation_eligibility(graph, compilation)

        self.assertEqual(first, second)
        self.assertEqual(len(first.options), 2)
        self.assertIn(
            "not automatic technique selection",
            first.interpretation,
        )

    def test_option_ceiling_fails_closed(self):
        graph, compilation, _service = service_fixture()

        with self.assertRaisesRegex(ValueError, "option ceiling"):
            plan_validation_eligibility(
                graph,
                compilation,
                limits=ValidationEligibilityLimits(max_options=1),
            )


if __name__ == "__main__":
    unittest.main()
