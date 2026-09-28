"""Authorization-first normalized cloud and hybrid intelligence ingestion.

Provider adapters are read-only and return a strict secret-free normalized JSON
snapshot. The importer emits ordinary Red engagement evidence so cloud resources,
identities, and observed relationships project into the unified attack graph.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Protocol
import json

from nightrecon_shared_core.contracts import EvidenceRecord
from nightrecon_shared_core.workspace import LocalWorkspace


_SCHEMA_VERSION = 1
_VALID_PROVIDERS = frozenset({"aws", "azure", "entra", "kubernetes"})
_VALID_ENDPOINT_TYPES = frozenset({"identity", "resource"})


def _required(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a nonblank, trimmed string")
    return value


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("cloud snapshot contains a duplicate JSON field")
        result[key] = value
    return result


def _provider(value: object) -> str:
    provider = _required(value, "provider")
    if provider not in _VALID_PROVIDERS:
        raise ValueError("unsupported cloud/hybrid provider")
    return provider


@dataclass(frozen=True)
class CloudHybridLimits:
    max_bytes: int = 1_000_000
    max_resources: int = 2_000
    max_identities: int = 2_000
    max_relationships: int = 10_000

    def __post_init__(self) -> None:
        if min(
            self.max_bytes, self.max_resources,
            self.max_identities, self.max_relationships,
        ) < 1:
            raise ValueError("cloud/hybrid limits must be positive")


@dataclass(frozen=True)
class CloudCollectionRequest:
    engagement_id: str
    source_id: str
    target: str
    limits: CloudHybridLimits = CloudHybridLimits()
    approval_present: bool = False

    def __post_init__(self) -> None:
        _required(self.engagement_id, "engagement_id")
        _required(self.source_id, "source_id")
        _required(self.target, "target")


class ReadOnlyCloudProvider(Protocol):
    def collect_normalized_snapshot(
        self, request: CloudCollectionRequest
    ) -> bytes: ...


@dataclass(frozen=True)
class CloudHybridImportResult:
    records: tuple[EvidenceRecord, ...]
    providers: tuple[str, ...]
    unresolved_relationships: int


@dataclass(frozen=True)
class CloudCollectionDenied(ValueError):
    reason_code: str
    reason: str

    def __str__(self) -> str:
        return f"{self.reason_code}: {self.reason}"


def _evidence_id(
    source_id: str,
    evidence_type: str,
    natural_key: str,
    observed_at: str,
) -> str:
    digest = sha256(
        f"{source_id}\x1f{evidence_type}\x1f{natural_key}\x1f{observed_at}".encode(
            "utf-8"
        )
    ).hexdigest()
    return f"red-cloud-{digest}"


def _asset_key(provider: str, identifier: str) -> str:
    return f"cloud:{provider}:resource:{identifier}"


def _identity_key(provider: str, identifier: str) -> str:
    return f"cloud:{provider}:identity:{identifier}"


def import_cloud_hybrid_snapshot(
    payload: bytes,
    *,
    engagement_id: str,
    source_id: str,
    observed_at: str,
    limits: CloudHybridLimits | None = None,
) -> CloudHybridImportResult:
    active = limits or CloudHybridLimits()
    _required(engagement_id, "engagement_id")
    _required(source_id, "source_id")
    _required(observed_at, "observed_at")
    if not isinstance(payload, bytes) or len(payload) > active.max_bytes:
        raise ValueError("cloud snapshot must be bytes within max_bytes")
    try:
        data = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("cloud snapshot is not valid UTF-8 JSON") from exc
    if (
        not isinstance(data, dict)
        or set(data) != {
            "schema_version", "resources", "identities", "relationships"
        }
        or data["schema_version"] != _SCHEMA_VERSION
    ):
        raise ValueError("cloud snapshot schema is not supported")
    resources = data["resources"]
    identities = data["identities"]
    relationships = data["relationships"]
    if not all(isinstance(item, list) for item in (resources, identities, relationships)):
        raise ValueError("cloud snapshot collections must be lists")
    if len(resources) > active.max_resources:
        raise ValueError("cloud snapshot exceeds max_resources")
    if len(identities) > active.max_identities:
        raise ValueError("cloud snapshot exceeds max_identities")
    if len(relationships) > active.max_relationships:
        raise ValueError("cloud snapshot exceeds max_relationships")

    records: list[EvidenceRecord] = []
    providers: set[str] = set()
    endpoints: set[tuple[str, str, str]] = set()

    for item in resources:
        if not isinstance(item, dict) or set(item) != {"provider", "id", "kind", "name"}:
            raise ValueError("cloud resource has unsupported fields")
        provider = _provider(item["provider"])
        identifier = _required(item["id"], "resource id")
        kind = _required(item["kind"], "resource kind")
        name = _required(item["name"], "resource name")
        key = _asset_key(provider, identifier)
        providers.add(provider)
        endpoints.add(("resource", provider, identifier))
        records.append(EvidenceRecord(
            engagement_id=engagement_id,
            evidence_id=_evidence_id(source_id, "asset.observation", key, observed_at),
            source_night="red",
            evidence_type="asset.observation",
            observed_at=observed_at,
            provenance=f"{source_id}#{provider}:resource:{identifier}",
            data={
                "asset_key": key,
                "label": name,
                "provider": provider,
                "resource_kind": kind,
            },
            limitations=("Read-only normalized cloud inventory evidence.",),
        ))

    for item in identities:
        if not isinstance(item, dict) or set(item) != {"provider", "id", "name"}:
            raise ValueError("cloud identity has unsupported fields")
        provider = _provider(item["provider"])
        identifier = _required(item["id"], "identity id")
        name = _required(item["name"], "identity name")
        key = _identity_key(provider, identifier)
        providers.add(provider)
        endpoints.add(("identity", provider, identifier))
        records.append(EvidenceRecord(
            engagement_id=engagement_id,
            evidence_id=_evidence_id(source_id, "identity.observation", key, observed_at),
            source_night="red",
            evidence_type="identity.observation",
            observed_at=observed_at,
            provenance=f"{source_id}#{provider}:identity:{identifier}",
            data={
                "identity_key": key,
                "label": name,
                "provider": provider,
            },
            limitations=("Read-only normalized cloud identity evidence.",),
        ))

    unresolved = 0
    for index, item in enumerate(relationships):
        required_fields = {
            "source_type", "source_provider", "source_id",
            "target_type", "target_provider", "target_id", "relationship",
        }
        if not isinstance(item, dict) or set(item) != required_fields:
            raise ValueError("cloud relationship has unsupported fields")
        source_type = _required(item["source_type"], "source_type")
        target_type = _required(item["target_type"], "target_type")
        if source_type not in _VALID_ENDPOINT_TYPES or target_type not in _VALID_ENDPOINT_TYPES:
            raise ValueError("cloud relationship endpoint type is unsupported")
        source_provider = _provider(item["source_provider"])
        target_provider = _provider(item["target_provider"])
        source_object_id = _required(item["source_id"], "source_id")
        target_object_id = _required(item["target_id"], "target_id")
        relationship = _required(item["relationship"], "relationship")
        source_ref = (source_type, source_provider, source_object_id)
        target_ref = (target_type, target_provider, target_object_id)
        if source_ref not in endpoints or target_ref not in endpoints:
            unresolved += 1
            continue
        source_key = (
            _identity_key(source_provider, source_object_id)
            if source_type == "identity"
            else _asset_key(source_provider, source_object_id)
        )
        target_key = (
            _identity_key(target_provider, target_object_id)
            if target_type == "identity"
            else _asset_key(target_provider, target_object_id)
        )
        natural = f"{source_key}->{relationship}->{target_key}:{index}"
        records.append(EvidenceRecord(
            engagement_id=engagement_id,
            evidence_id=_evidence_id(
                source_id=source_id,
                evidence_type="graph.relationship",
                natural_key=natural,
                observed_at=observed_at,
            ),
            source_night="red",
            evidence_type="graph.relationship",
            observed_at=observed_at,
            provenance=f"{source_id}#relationship-{index}",
            data={
                "source_kind": "identity" if source_type == "identity" else "asset",
                "source_key": source_key,
                "target_kind": "identity" if target_type == "identity" else "asset",
                "target_key": target_key,
                "relationship": relationship,
                "evidence_state": "observed",
            },
            limitations=("Observed provider relationship; no exploitability verdict.",),
        ))

    return CloudHybridImportResult(
        records=tuple(sorted(records, key=lambda item: item.evidence_id)),
        providers=tuple(sorted(providers)),
        unresolved_relationships=unresolved,
    )


def collect_authorized_cloud_intelligence(
    workspace: LocalWorkspace,
    provider: ReadOnlyCloudProvider,
    request: CloudCollectionRequest,
    *,
    now: datetime | None = None,
) -> CloudHybridImportResult:
    decision = workspace.authorize_action(
        request.engagement_id,
        capability="cloud.collect",
        target=request.target,
        impact="standard",
        approval_present=request.approval_present,
        consume=True,
        now=now,
    )
    if not decision.allowed:
        raise CloudCollectionDenied(decision.reason_code, decision.reason)
    observed = datetime.now(timezone.utc) if now is None else now
    if observed.tzinfo is None:
        raise ValueError("now must include a timezone")
    payload = provider.collect_normalized_snapshot(request)
    return import_cloud_hybrid_snapshot(
        payload,
        engagement_id=request.engagement_id,
        source_id=request.source_id,
        observed_at=observed.isoformat(),
        limits=request.limits,
    )
