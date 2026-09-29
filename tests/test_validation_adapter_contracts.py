"""v0.43 Batch 3 adapter/precondition/postcondition contract tests."""

from __future__ import annotations

from dataclasses import replace
import unittest

from nightrecon_red_engine.attack_path_atlas import (
    build_cross_domain_attack_path_atlas,
)
from nightrecon_red_engine.controlled_validation import ValidationObservation
from nightrecon_red_engine.graph_builder import IdentityGraphBuilder
from nightrecon_red_engine.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
)
from nightrecon_red_engine.validation_adapter_contracts import (
    BUILTIN_VALIDATION_ADAPTER_CONTRACT_REGISTRY,
    ValidationAdapterContract,
    ValidationAdapterContractRegistry,
    ValidationAdapterPostcondition,
    assert_contract_matches_technique,
    bind_validation_eligibility_option,
    check_validation_observation_contract,
)
from nightrecon_red_engine.validation_candidates import (
    compile_validation_candidates,
)
from nightrecon_red_engine.validation_eligibility import (
    plan_validation_eligibility,
)
from nightrecon_red_engine.validation_techniques import (
    BUILTIN_VALIDATION_TECHNIQUE_REGISTRY,
)


def provenance(key):
    return (GraphProvenance("engagement-evidence", key),)


def fixture():
    identity = GraphNode.create(
        kind=GraphNodeKind.IDENTITY,
        natural_key="identity:contract",
        label="Contract identity",
        provenance=provenance("identity"),
    )
    service = GraphNode.create(
        kind=GraphNodeKind.SERVICE,
        natural_key="192.0.2.44:443/tcp",
        label="https",
        provenance=provenance("service"),
        properties=(
            ("address", "192.0.2.44"),
            ("port", "443"),
            ("protocol", "tcp"),
            ("tls_certificate_sha256", "abc123"),
        ),
    )
    critical = GraphNode.create(
        kind=GraphNodeKind.CRITICAL_ASSET,
        natural_key="critical:contract",
        label="Critical contract target",
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
    graph = builder.build()
    atlas = build_cross_domain_attack_path_atlas(
        graph,
        start_kinds=(GraphNodeKind.IDENTITY,),
    )
    compilation = compile_validation_candidates(graph, atlas)
    eligibility = plan_validation_eligibility(graph, compilation)
    return graph, eligibility, service


class ValidationAdapterContractTests(unittest.TestCase):
    def test_builtin_contracts_exactly_match_reviewed_techniques(self):
        contracts = BUILTIN_VALIDATION_ADAPTER_CONTRACT_REGISTRY.list()
        techniques = BUILTIN_VALIDATION_TECHNIQUE_REGISTRY.list()

        self.assertEqual(
            tuple(item.technique_id for item in contracts),
            tuple(item.technique_id for item in techniques),
        )
        for technique in techniques:
            assert_contract_matches_technique(
                BUILTIN_VALIDATION_ADAPTER_CONTRACT_REGISTRY.for_technique(
                    technique.technique_id
                ),
                technique,
            )

    def test_explicit_eligibility_option_binds_without_execution_surface(self):
        graph, eligibility, service = fixture()
        option = next(
            item for item in eligibility.options
            if item.technique_id == "service.tls-property-proof"
        )

        binding = bind_validation_eligibility_option(graph, option)

        self.assertEqual(binding.target_node_id, service.node_id)
        self.assertEqual(binding.execution_mode, "contract-only")
        self.assertEqual(binding.side_effect_mode, "none")
        self.assertEqual(
            binding.expected_evidence_keys,
            ("tls_version", "cipher", "certificate_sha256"),
        )
        serialized = str(binding.to_dict()).lower()
        self.assertNotIn("payload", serialized)
        self.assertNotIn("command", serialized)

    def test_stale_target_precondition_fails_closed(self):
        graph, eligibility, service = fixture()
        option = next(
            item for item in eligibility.options
            if item.technique_id == "service.tls-property-proof"
        )
        replacement = GraphNode.create(
            kind=GraphNodeKind.SERVICE,
            natural_key=service.natural_key,
            label=service.label,
            provenance=service.provenance,
            properties=(
                ("address", "192.0.2.44"),
                ("port", "443"),
                ("protocol", "tcp"),
            ),
        )
        builder = IdentityGraphBuilder()
        for node in graph.nodes:
            builder.add_node(
                replacement if node.node_id == service.node_id else node
            )
        for edge in graph.edges:
            builder.add_edge(edge)
        stale_graph = builder.build()

        with self.assertRaisesRegex(ValueError, "preconditions"):
            bind_validation_eligibility_option(stale_graph, option)

    def test_tampered_eligibility_identifier_fails_closed(self):
        graph, eligibility, _service = fixture()
        option = eligibility.options[0]

        with self.assertRaisesRegex(ValueError, "identifier"):
            bind_validation_eligibility_option(
                graph,
                replace(option, eligibility_id="validation-eligibility-invalid"),
            )

    def test_confirmed_observation_requires_exact_contract_evidence(self):
        contract = (
            BUILTIN_VALIDATION_ADAPTER_CONTRACT_REGISTRY.for_technique(
                "service.tls-property-proof"
            )
        )
        valid = check_validation_observation_contract(
            contract,
            ValidationObservation(
                confirmed=True,
                summary="TLS metadata observed.",
                evidence={
                    "tls_version": "TLSv1.3",
                    "cipher": "TLS_AES_256_GCM_SHA384",
                    "certificate_sha256": "abc123",
                },
            ),
        )
        self.assertTrue(valid.valid)
        self.assertEqual(valid.reason, "contract-satisfied")

        missing = check_validation_observation_contract(
            contract,
            ValidationObservation(
                confirmed=True,
                summary="Incomplete confirmation.",
                evidence={
                    "tls_version": "TLSv1.3",
                    "cipher": "TLS_AES_256_GCM_SHA384",
                },
            ),
        )
        self.assertFalse(missing.valid)
        self.assertEqual(
            missing.missing_keys,
            ("certificate_sha256",),
        )

    def test_unexpected_postcondition_evidence_fails_closed(self):
        contract = (
            BUILTIN_VALIDATION_ADAPTER_CONTRACT_REGISTRY.for_technique(
                "service.tcp-property-proof"
            )
        )
        result = check_validation_observation_contract(
            contract,
            ValidationObservation(
                confirmed=False,
                summary="Partial proof.",
                evidence={
                    "transport": "tcp",
                    "debug_detail": "not allowed by contract",
                },
            ),
        )
        self.assertFalse(result.valid)
        self.assertEqual(result.reason, "unexpected-evidence")
        self.assertEqual(result.unexpected_keys, ("debug_detail",))

    def test_contract_drift_from_technique_is_rejected(self):
        technique = BUILTIN_VALIDATION_TECHNIQUE_REGISTRY.get(
            "service.tcp-property-proof"
        )
        original = (
            BUILTIN_VALIDATION_ADAPTER_CONTRACT_REGISTRY.for_technique(
                technique.technique_id
            )
        )
        drifted = ValidationAdapterContract(
            contract_id=original.contract_id,
            technique_id=original.technique_id,
            adapter_kind=original.adapter_kind,
            target_kinds=original.target_kinds,
            preconditions=original.preconditions,
            postconditions=(
                ValidationAdapterPostcondition("transport"),
            ),
        )
        with self.assertRaisesRegex(ValueError, "does not match"):
            assert_contract_matches_technique(drifted, technique)

    def test_contract_registry_rejects_duplicate_technique_bindings(self):
        contract = (
            BUILTIN_VALIDATION_ADAPTER_CONTRACT_REGISTRY.for_technique(
                "service.tcp-property-proof"
            )
        )
        with self.assertRaisesRegex(ValueError, "unique per technique"):
            ValidationAdapterContractRegistry((contract, contract))


if __name__ == "__main__":
    unittest.main()
