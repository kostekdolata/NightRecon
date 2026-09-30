"""Deterministic White Night ROE to shared-core policy compilation.

Compilation is local and network-free. It can only preserve or narrow authoring
intent. If a White constraint cannot be represented exactly by the shared-core
execution policy, compilation fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import ipaddress
import json
from typing import Any, Mapping

from nightrecon_shared_core.authorization import Target, TargetType, parse_target
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy

from nightrecon_white_engine.engagement_domain import EngagementDefinition


POLICY_BUNDLE_SCHEMA_VERSION = 1
POLICY_COMPILER_VERSION = 1

_INTRUSIVENESS_TO_IMPACT = {
    "passive": "low",
    "safe-active": "standard",
    "intrusive": "high",
}


class PolicyCompilationError(ValueError):
    """White ROE cannot be represented safely as shared-core policy."""


def _canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _fingerprint(payload: Mapping[str, Any]) -> str:
    return sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _network_for_target(target: Target) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if target.target_type == TargetType.CIDR:
        return ipaddress.ip_network(target.value, strict=False)
    if target.target_type in (TargetType.IPV4, TargetType.IPV6):
        address = ipaddress.ip_address(target.value)
        prefix = 32 if address.version == 4 else 128
        return ipaddress.ip_network(f"{address}/{prefix}", strict=False)
    return None


def _subtract_network(
    allowed: ipaddress.IPv4Network | ipaddress.IPv6Network,
    excluded: ipaddress.IPv4Network | ipaddress.IPv6Network,
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    if allowed.version != excluded.version or not allowed.overlaps(excluded):
        return (allowed,)
    if allowed.subnet_of(excluded):
        return ()
    if excluded.subnet_of(allowed):
        return tuple(allowed.address_exclude(excluded))
    # Aligned CIDRs should never reach a partial-overlap state. Fail closed if
    # a future target representation changes that assumption.
    raise PolicyCompilationError("scope exclusion cannot be represented exactly")


def _effective_scope(
    allowed_values: tuple[str, ...],
    excluded_values: tuple[str, ...],
) -> tuple[str, ...]:
    allowed = tuple(parse_target(value) for value in allowed_values)
    excluded = tuple(parse_target(value) for value in excluded_values)

    excluded_hostnames = {
        target.value for target in excluded
        if target.target_type == TargetType.HOSTNAME
    }
    excluded_networks = tuple(
        network
        for target in excluded
        if (network := _network_for_target(target)) is not None
    )

    result: set[str] = set()

    for target in allowed:
        if target.target_type == TargetType.HOSTNAME:
            if target.value not in excluded_hostnames:
                result.add(target.value)
            continue

        if target.target_type in (TargetType.IPV4, TargetType.IPV6):
            address = ipaddress.ip_address(target.value)
            if any(
                address.version == network.version and address in network
                for network in excluded_networks
            ):
                continue
            # Preserve exact-address semantics. Converting to /32 or /128 would
            # also authorize a CIDR-shaped target under shared-core matching.
            result.add(str(address))
            continue

        if target.target_type == TargetType.CIDR:
            source_network = ipaddress.ip_network(target.value, strict=False)
            pieces: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
                source_network,
            )
            for excluded_network in excluded_networks:
                next_pieces: list[
                    ipaddress.IPv4Network | ipaddress.IPv6Network
                ] = []
                for piece in pieces:
                    next_pieces.extend(_subtract_network(piece, excluded_network))
                pieces = tuple(next_pieces)
                if not pieces:
                    break
            result.update(str(piece) for piece in pieces)
            continue

        raise PolicyCompilationError("unsupported scope target type")

    if not result:
        raise PolicyCompilationError(
            "ROE exclusions remove the entire effective scope"
        )
    return tuple(sorted(result))


@dataclass(frozen=True)
class CompiledPolicyBundle:
    """Integrity-bound policy projection from one immutable engagement version."""

    engagement_id: str
    engagement_version: int
    engagement_fingerprint: str
    roe_version: int
    roe_fingerprint: str
    policy: EngagementExecutionPolicy
    compiler_version: int = POLICY_COMPILER_VERSION
    schema_version: int = POLICY_BUNDLE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != POLICY_BUNDLE_SCHEMA_VERSION:
            raise PolicyCompilationError("unsupported compiled policy bundle schema")
        if self.compiler_version != POLICY_COMPILER_VERSION:
            raise PolicyCompilationError("unsupported policy compiler version")
        if self.policy.engagement_id != self.engagement_id:
            raise PolicyCompilationError(
                "compiled policy engagement does not match bundle"
            )
        for name, value in (
            ("engagement_fingerprint", self.engagement_fingerprint),
            ("roe_fingerprint", self.roe_fingerprint),
        ):
            if (
                not isinstance(value, str)
                or len(value) != 64
                or any(character not in "0123456789abcdef" for character in value)
            ):
                raise PolicyCompilationError(f"{name} must be a lowercase SHA-256")

    @property
    def policy_fingerprint(self) -> str:
        return _fingerprint(self.policy.to_dict())

    def _bundle_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "compiler_version": self.compiler_version,
            "engagement_id": self.engagement_id,
            "engagement_version": self.engagement_version,
            "engagement_fingerprint": self.engagement_fingerprint,
            "roe_version": self.roe_version,
            "roe_fingerprint": self.roe_fingerprint,
            "policy_fingerprint": self.policy_fingerprint,
            "policy": self.policy.to_dict(),
        }

    @property
    def bundle_fingerprint(self) -> str:
        return _fingerprint(self._bundle_payload())

    def to_dict(self) -> dict[str, Any]:
        payload = self._bundle_payload()
        payload["bundle_fingerprint"] = self.bundle_fingerprint
        return payload

    def to_json(self) -> str:
        return _canonical_json(self.to_dict())

    def verify_integrity(self) -> bool:
        # Construction already validates structural invariants. Recomputing both
        # fingerprints gives callers an explicit verification hook.
        payload = self.to_dict()
        return (
            payload["policy_fingerprint"] == self.policy_fingerprint
            and payload["bundle_fingerprint"] == self.bundle_fingerprint
        )

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "CompiledPolicyBundle":
        required = {
            "schema_version",
            "compiler_version",
            "engagement_id",
            "engagement_version",
            "engagement_fingerprint",
            "roe_version",
            "roe_fingerprint",
            "policy_fingerprint",
            "bundle_fingerprint",
            "policy",
        }
        if not isinstance(payload, Mapping) or set(payload) != required:
            raise PolicyCompilationError(
                "compiled policy bundle schema is not supported"
            )
        policy_payload = payload["policy"]
        if not isinstance(policy_payload, Mapping):
            raise PolicyCompilationError("compiled policy must be an object")
        try:
            policy = EngagementExecutionPolicy.from_dict(policy_payload)
        except ValueError as exc:
            raise PolicyCompilationError(str(exc)) from exc

        bundle = cls(
            schema_version=payload["schema_version"],
            compiler_version=payload["compiler_version"],
            engagement_id=payload["engagement_id"],
            engagement_version=payload["engagement_version"],
            engagement_fingerprint=payload["engagement_fingerprint"],
            roe_version=payload["roe_version"],
            roe_fingerprint=payload["roe_fingerprint"],
            policy=policy,
        )
        if payload["policy_fingerprint"] != bundle.policy_fingerprint:
            raise PolicyCompilationError(
                "compiled policy fingerprint verification failed"
            )
        if payload["bundle_fingerprint"] != bundle.bundle_fingerprint:
            raise PolicyCompilationError(
                "compiled policy bundle fingerprint verification failed"
            )
        return bundle

    @classmethod
    def from_json(cls, payload: str) -> "CompiledPolicyBundle":
        try:
            decoded = json.loads(payload)
        except (TypeError, json.JSONDecodeError) as exc:
            raise PolicyCompilationError(
                "compiled policy bundle is not valid JSON"
            ) from exc
        return cls.from_dict(decoded)


def compile_engagement_policy(
    engagement: EngagementDefinition,
) -> CompiledPolicyBundle:
    """Compile one immutable White engagement into shared-core policy.

    The compiler never publishes or persists the resulting execution policy.
    Publication/revocation workflows remain later White Night responsibilities.
    """

    roe = engagement.roe
    max_impact = _INTRUSIVENESS_TO_IMPACT.get(roe.max_intrusiveness)
    if max_impact is None:
        raise PolicyCompilationError(
            "destructive intrusiveness is not representable by the shared-core "
            "execution policy and cannot be compiled"
        )

    scope = _effective_scope(roe.scope.allowed, roe.scope.excluded)

    try:
        policy = EngagementExecutionPolicy(
            engagement_id=engagement.engagement_id,
            scope=scope,
            valid_from=roe.valid_from,
            valid_until=roe.valid_until,
            max_actions=roe.max_actions,
            permitted_capabilities=tuple(sorted(roe.allowed_techniques)),
            max_impact=max_impact,
            approval_required_capabilities=(),
        )
    except ValueError as exc:
        raise PolicyCompilationError(
            f"ROE cannot be represented safely as shared-core policy: {exc}"
        ) from exc

    return CompiledPolicyBundle(
        engagement_id=engagement.engagement_id,
        engagement_version=engagement.version,
        engagement_fingerprint=engagement.fingerprint,
        roe_version=roe.version,
        roe_fingerprint=roe.fingerprint,
        policy=policy,
    )
