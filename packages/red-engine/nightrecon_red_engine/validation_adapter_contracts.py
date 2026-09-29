"""Metadata-only adapter and pre/postcondition contracts for v0.43.

Batch 3 binds reviewed eligibility options to immutable read-only proof
contracts. This module contains no adapter callables, commands, payloads,
credentials, worker execution, authorization consumption, or network activity.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import re
from typing import Iterable

from nightrecon_red_engine.controlled_validation import ValidationObservation
from nightrecon_red_engine.graph_models import GraphNode, IdentityGraph
from nightrecon_red_engine.graph_validation import assert_valid_identity_graph
from nightrecon_red_engine.validation_eligibility import (
    EligibilityEvidenceSource,
    ValidationEligibilityOption,
    classify_validation_target,
    validation_eligibility_id,
)
from nightrecon_red_engine.validation_techniques import (
    BUILTIN_VALIDATION_TECHNIQUES,
    BUILTIN_VALIDATION_TECHNIQUE_REGISTRY,
    ValidationTechniqueDefinition,
    ValidationTechniqueRegistry,
)


_CONTRACT_ID_RE = re.compile(r"^[a-z0-9]+(?:[.-][a-z0-9]+)*$")
_PROPERTY_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_VALID_PRECONDITION_OPERATORS = frozenset({"present", "equals"})
_VALID_TARGET_KINDS = frozenset({"asset", "service", "web", "api"})
_SECRET_LIKE_FRAGMENTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "cookie",
    "authorization",
    "api_key",
    "apikey",
    "private_key",
    "session",
)

CONTRACT_INTERPRETATION = (
    "Adapter contracts are metadata-only compatibility boundaries. A contract "
    "binding does not execute an adapter, consume authorization, establish "
    "exploitability, or grant permission to validate."
)


def _required(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a nonblank, trimmed string")
    return value


def _safe_key(value: str, field: str) -> str:
    _required(value, field)
    if not _PROPERTY_KEY_RE.fullmatch(value):
        raise ValueError(f"{field} must be a canonical property key")
    lowered = value.lower()
    if any(fragment in lowered for fragment in _SECRET_LIKE_FRAGMENTS):
        raise ValueError(f"{field} must not be secret-like")
    return value


@dataclass(frozen=True, order=True)
class ValidationAdapterPrecondition:
    """One exact graph-property prerequisite for a reviewed adapter contract."""

    key: str
    operator: str
    value: str = ""

    def __post_init__(self) -> None:
        _safe_key(self.key, "precondition key")
        if self.operator not in _VALID_PRECONDITION_OPERATORS:
            raise ValueError("precondition operator must be present or equals")
        if self.operator == "present":
            if self.value:
                raise ValueError("present preconditions must not define a value")
        else:
            _required(self.value, "precondition value")

    def to_dict(self) -> dict[str, str]:
        return {
            "key": self.key,
            "operator": self.operator,
            "value": self.value,
        }


@dataclass(frozen=True, order=True)
class ValidationAdapterPostcondition:
    """One allowed top-level evidence key produced by a reviewed adapter."""

    evidence_key: str
    requirement: str = "present-when-confirmed"

    def __post_init__(self) -> None:
        _safe_key(self.evidence_key, "postcondition evidence key")
        if self.requirement != "present-when-confirmed":
            raise ValueError(
                "postcondition requirement must be present-when-confirmed"
            )

    def to_dict(self) -> dict[str, str]:
        return {
            "evidence_key": self.evidence_key,
            "requirement": self.requirement,
        }


@dataclass(frozen=True)
class ValidationAdapterContract:
    """Immutable non-executable contract for one reviewed technique."""

    contract_id: str
    technique_id: str
    adapter_kind: str
    target_kinds: tuple[str, ...]
    preconditions: tuple[ValidationAdapterPrecondition, ...]
    postconditions: tuple[ValidationAdapterPostcondition, ...]
    side_effect_mode: str = "none"
    execution_mode: str = "contract-only"

    def __post_init__(self) -> None:
        _required(self.contract_id, "contract_id")
        _required(self.technique_id, "technique_id")
        if not _CONTRACT_ID_RE.fullmatch(self.contract_id):
            raise ValueError("contract_id must be lowercase canonical metadata")
        if not _CONTRACT_ID_RE.fullmatch(self.technique_id):
            raise ValueError("technique_id must be lowercase canonical metadata")
        if self.adapter_kind != "read-only-proof":
            raise ValueError("adapter_kind must remain read-only-proof")
        if self.side_effect_mode != "none":
            raise ValueError("Batch 3 contracts must declare no side effects")
        if self.execution_mode != "contract-only":
            raise ValueError("Batch 3 contracts must remain contract-only")

        if not self.target_kinds:
            raise ValueError("contract target_kinds must not be empty")
        if len(self.target_kinds) != len(set(self.target_kinds)):
            raise ValueError("contract target_kinds must not contain duplicates")
        if any(kind not in _VALID_TARGET_KINDS for kind in self.target_kinds):
            raise ValueError("contract target kind is not supported")

        precondition_keys = tuple(item.key for item in self.preconditions)
        if len(precondition_keys) != len(set(precondition_keys)):
            raise ValueError("contract preconditions must not repeat keys")

        postcondition_keys = tuple(
            item.evidence_key for item in self.postconditions
        )
        if not postcondition_keys:
            raise ValueError("contract postconditions must not be empty")
        if len(postcondition_keys) != len(set(postcondition_keys)):
            raise ValueError("contract postconditions must not repeat keys")

    def to_dict(self) -> dict[str, object]:
        return {
            "contract_id": self.contract_id,
            "technique_id": self.technique_id,
            "adapter_kind": self.adapter_kind,
            "target_kinds": list(self.target_kinds),
            "preconditions": [item.to_dict() for item in self.preconditions],
            "postconditions": [item.to_dict() for item in self.postconditions],
            "side_effect_mode": self.side_effect_mode,
            "execution_mode": self.execution_mode,
            "interpretation": CONTRACT_INTERPRETATION,
        }


def adapter_contract_from_technique(
    technique: ValidationTechniqueDefinition,
) -> ValidationAdapterContract:
    """Build the exact non-executable contract declared by reviewed metadata."""

    preconditions = tuple(
        ValidationAdapterPrecondition(key=key, operator="present")
        for key in technique.eligibility_required_properties
    ) + tuple(
        ValidationAdapterPrecondition(
            key=key,
            operator="equals",
            value=value,
        )
        for key, value in technique.eligibility_required_values
    )
    postconditions = tuple(
        ValidationAdapterPostcondition(evidence_key=key)
        for key in technique.evidence_keys
    )
    return ValidationAdapterContract(
        contract_id=f"{technique.technique_id}.contract.v1",
        technique_id=technique.technique_id,
        adapter_kind=technique.adapter_kind,
        target_kinds=technique.target_kinds,
        preconditions=preconditions,
        postconditions=postconditions,
    )


def assert_contract_matches_technique(
    contract: ValidationAdapterContract,
    technique: ValidationTechniqueDefinition,
) -> None:
    expected = adapter_contract_from_technique(technique)
    if (
        contract.technique_id != expected.technique_id
        or contract.adapter_kind != expected.adapter_kind
        or contract.target_kinds != expected.target_kinds
        or contract.preconditions != expected.preconditions
        or contract.postconditions != expected.postconditions
        or contract.side_effect_mode != "none"
        or contract.execution_mode != "contract-only"
    ):
        raise ValueError("adapter contract does not match reviewed technique metadata")


class ValidationAdapterContractRegistry:
    """Deterministic registry containing metadata contracts, not callables."""

    def __init__(self, contracts: Iterable[ValidationAdapterContract]):
        ordered = tuple(
            sorted(tuple(contracts), key=lambda item: item.technique_id)
        )
        technique_ids = tuple(item.technique_id for item in ordered)
        contract_ids = tuple(item.contract_id for item in ordered)
        if len(technique_ids) != len(set(technique_ids)):
            raise ValueError("adapter contracts must be unique per technique")
        if len(contract_ids) != len(set(contract_ids)):
            raise ValueError("adapter contract ids must be unique")
        self._contracts = ordered
        self._by_technique = {
            item.technique_id: item for item in ordered
        }

    def list(self) -> tuple[ValidationAdapterContract, ...]:
        return self._contracts

    def for_technique(self, technique_id: str) -> ValidationAdapterContract:
        _required(technique_id, "technique_id")
        try:
            return self._by_technique[technique_id]
        except KeyError as exc:
            raise ValueError(
                f"no adapter contract for technique: {technique_id}"
            ) from exc


BUILTIN_VALIDATION_ADAPTER_CONTRACTS = tuple(
    adapter_contract_from_technique(technique)
    for technique in BUILTIN_VALIDATION_TECHNIQUES
)

BUILTIN_VALIDATION_ADAPTER_CONTRACT_REGISTRY = (
    ValidationAdapterContractRegistry(
        BUILTIN_VALIDATION_ADAPTER_CONTRACTS
    )
)


@dataclass(frozen=True)
class ValidationPreconditionCheck:
    satisfied: bool
    failed_keys: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "satisfied": self.satisfied,
            "failed_keys": list(self.failed_keys),
        }


def evaluate_validation_preconditions(
    contract: ValidationAdapterContract,
    target: GraphNode,
) -> ValidationPreconditionCheck:
    """Evaluate only existing graph properties; perform no live activity."""

    properties = dict(target.properties)
    failed: list[str] = []
    for condition in contract.preconditions:
        if condition.operator == "present":
            if not properties.get(condition.key):
                failed.append(condition.key)
        elif properties.get(condition.key) != condition.value:
            failed.append(condition.key)

    return ValidationPreconditionCheck(
        satisfied=not failed,
        failed_keys=tuple(sorted(failed)),
    )


@dataclass(frozen=True)
class ValidationAdapterBinding:
    """One deterministic non-executable eligibility-to-contract binding."""

    binding_id: str
    eligibility_id: str
    candidate_id: str
    path_id: str
    technique_id: str
    contract_id: str
    target_node_id: str
    target_kind: str
    expected_evidence_keys: tuple[str, ...]
    impact: str
    requires_approval: bool
    adapter_kind: str
    cleanup_mode: str
    side_effect_mode: str
    execution_mode: str = "contract-only"
    interpretation: str = CONTRACT_INTERPRETATION

    def to_dict(self) -> dict[str, object]:
        return {
            "binding_id": self.binding_id,
            "eligibility_id": self.eligibility_id,
            "candidate_id": self.candidate_id,
            "path_id": self.path_id,
            "technique_id": self.technique_id,
            "contract_id": self.contract_id,
            "target_node_id": self.target_node_id,
            "target_kind": self.target_kind,
            "expected_evidence_keys": list(self.expected_evidence_keys),
            "impact": self.impact,
            "requires_approval": self.requires_approval,
            "adapter_kind": self.adapter_kind,
            "cleanup_mode": self.cleanup_mode,
            "side_effect_mode": self.side_effect_mode,
            "execution_mode": self.execution_mode,
            "interpretation": self.interpretation,
        }


def _expected_provenance(
    node: GraphNode,
) -> tuple[EligibilityEvidenceSource, ...]:
    return tuple(
        EligibilityEvidenceSource(item.source_type, item.source_id)
        for item in node.provenance
    )


def validation_binding_id(
    eligibility_id: str,
    contract_id: str,
    target_node_id: str,
) -> str:
    """Return the stable identifier for one eligibility/contract/target binding."""

    for value, field in (
        (eligibility_id, "eligibility_id"),
        (contract_id, "contract_id"),
        (target_node_id, "target_node_id"),
    ):
        _required(value, field)
    material = "\x1f".join(
        (eligibility_id, contract_id, target_node_id)
    ).encode("utf-8")
    return "validation-binding-" + sha256(material).hexdigest()


def bind_validation_eligibility_option(
    graph: IdentityGraph,
    option: ValidationEligibilityOption,
    *,
    contract_registry: ValidationAdapterContractRegistry = (
        BUILTIN_VALIDATION_ADAPTER_CONTRACT_REGISTRY
    ),
    technique_registry: ValidationTechniqueRegistry = (
        BUILTIN_VALIDATION_TECHNIQUE_REGISTRY
    ),
) -> ValidationAdapterBinding:
    """Bind one explicit option to its reviewed contract without execution."""

    assert_valid_identity_graph(graph)
    if option.execution_mode != "proposal-only":
        raise ValueError("eligibility option must remain proposal-only")

    technique = technique_registry.get(option.technique_id)
    if option.expected_evidence_keys != technique.evidence_keys:
        raise ValueError("eligibility expected evidence no longer matches technique")
    if option.impact != technique.impact:
        raise ValueError("eligibility impact no longer matches technique")
    if option.requires_approval != technique.requires_approval:
        raise ValueError("eligibility approval metadata no longer matches technique")
    if option.adapter_kind != technique.adapter_kind:
        raise ValueError("eligibility adapter kind no longer matches technique")
    if option.cleanup_mode != technique.cleanup_mode:
        raise ValueError("eligibility cleanup mode no longer matches technique")

    target = next(
        (
            node
            for node in graph.nodes
            if node.node_id == option.target_node_id
        ),
        None,
    )
    if target is None:
        raise ValueError("eligibility target node is missing from graph")

    target_kind = classify_validation_target(target)
    if target_kind is None or target_kind != option.target_kind:
        raise ValueError("eligibility target classification is stale")
    if target_kind not in technique.target_kinds:
        raise ValueError("eligibility target kind no longer matches technique")
    if option.target_provenance != _expected_provenance(target):
        raise ValueError("eligibility target provenance is stale")

    expected_eligibility_id = validation_eligibility_id(
        option.candidate_id,
        option.technique_id,
        option.target_node_id,
    )
    if option.eligibility_id != expected_eligibility_id:
        raise ValueError("eligibility identifier is stale or invalid")

    contract = contract_registry.for_technique(option.technique_id)
    assert_contract_matches_technique(contract, technique)

    preconditions = evaluate_validation_preconditions(contract, target)
    if not preconditions.satisfied:
        raise ValueError(
            "adapter contract preconditions are not satisfied: "
            + ",".join(preconditions.failed_keys)
        )

    return ValidationAdapterBinding(
        binding_id=validation_binding_id(
            option.eligibility_id,
            contract.contract_id,
            option.target_node_id,
        ),
        eligibility_id=option.eligibility_id,
        candidate_id=option.candidate_id,
        path_id=option.path_id,
        technique_id=option.technique_id,
        contract_id=contract.contract_id,
        target_node_id=option.target_node_id,
        target_kind=option.target_kind,
        expected_evidence_keys=option.expected_evidence_keys,
        impact=option.impact,
        requires_approval=option.requires_approval,
        adapter_kind=option.adapter_kind,
        cleanup_mode=option.cleanup_mode,
        side_effect_mode=contract.side_effect_mode,
    )


@dataclass(frozen=True)
class ValidationPostconditionCheck:
    valid: bool
    reason: str
    required_keys: tuple[str, ...]
    observed_keys: tuple[str, ...]
    missing_keys: tuple[str, ...]
    unexpected_keys: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "reason": self.reason,
            "required_keys": list(self.required_keys),
            "observed_keys": list(self.observed_keys),
            "missing_keys": list(self.missing_keys),
            "unexpected_keys": list(self.unexpected_keys),
        }


def check_validation_observation_contract(
    contract: ValidationAdapterContract,
    observation: ValidationObservation,
) -> ValidationPostconditionCheck:
    """Validate returned evidence shape only; never execute an adapter."""

    required = tuple(
        sorted(item.evidence_key for item in contract.postconditions)
    )
    observed = tuple(sorted(observation.evidence.keys()))
    required_set = set(required)
    observed_set = set(observed)

    unexpected = tuple(sorted(observed_set - required_set))
    missing = (
        tuple(sorted(required_set - observed_set))
        if observation.confirmed
        else ()
    )

    if unexpected and missing:
        reason = "postcondition-mismatch"
    elif unexpected:
        reason = "unexpected-evidence"
    elif missing:
        reason = "missing-confirmed-evidence"
    else:
        reason = "contract-satisfied"

    return ValidationPostconditionCheck(
        valid=not unexpected and not missing,
        reason=reason,
        required_keys=required,
        observed_keys=observed,
        missing_keys=missing,
        unexpected_keys=unexpected,
    )
