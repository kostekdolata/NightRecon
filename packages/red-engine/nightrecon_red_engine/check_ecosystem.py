"""Local policy/catalog layer for verified declarative Red check packs."""

from __future__ import annotations

from dataclasses import dataclass
import re

from nightrecon_red_engine.assessment_engine import CheckIntrusiveness
from nightrecon_red_engine.check_packs import CheckPack


_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_ORDER = {
    CheckIntrusiveness.PASSIVE: 0,
    CheckIntrusiveness.SAFE_ACTIVE: 1,
    CheckIntrusiveness.INTRUSIVE: 2,
    CheckIntrusiveness.DESTRUCTIVE: 3,
}


def _required(value: str, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a nonblank, trimmed string")
    return value


@dataclass(frozen=True)
class EcosystemPackProvenance:
    signer_key_id: str
    source_feed_id: str
    sha256: str

    def __post_init__(self) -> None:
        _required(self.signer_key_id, "signer_key_id")
        _required(self.source_feed_id, "source_feed_id")
        if _SHA256.fullmatch(self.sha256) is None:
            raise ValueError("sha256 must contain 64 hexadecimal characters")


@dataclass(frozen=True)
class VerifiedEcosystemPack:
    pack: CheckPack
    provenance: EcosystemPackProvenance


@dataclass(frozen=True)
class CheckEcosystemPolicy:
    trusted_signers: tuple[str, ...]
    allowed_capabilities: tuple[str, ...] = ()
    max_intrusiveness: CheckIntrusiveness = CheckIntrusiveness.SAFE_ACTIVE
    max_checks_per_pack: int = 256

    def __post_init__(self) -> None:
        if not self.trusted_signers:
            raise ValueError("trusted_signers must not be empty")
        if len(self.trusted_signers) != len(set(self.trusted_signers)):
            raise ValueError("trusted_signers must be unique")
        if len(self.allowed_capabilities) != len(set(self.allowed_capabilities)):
            raise ValueError("allowed_capabilities must be unique")
        if self.max_checks_per_pack < 1:
            raise ValueError("max_checks_per_pack must be positive")


@dataclass(frozen=True)
class CheckPackEligibility:
    pack_id: str
    version: str
    eligible: bool
    reason_codes: tuple[str, ...]


def evaluate_pack_eligibility(
    artifact: VerifiedEcosystemPack,
    policy: CheckEcosystemPolicy,
) -> CheckPackEligibility:
    reasons: list[str] = []
    pack = artifact.pack

    if artifact.provenance.signer_key_id not in policy.trusted_signers:
        reasons.append("untrusted_signer")
    if len(pack.checks) > policy.max_checks_per_pack:
        reasons.append("check_count_exceeded")

    allowed = set(policy.allowed_capabilities)
    for check in pack.checks:
        if _ORDER[check.metadata.intrusiveness] > _ORDER[policy.max_intrusiveness]:
            reasons.append(f"intrusiveness_exceeded:{check.metadata.check_id}")
        missing = sorted(set(check.metadata.required_capabilities) - allowed)
        if missing:
            reasons.append(
                f"capability_not_allowed:{check.metadata.check_id}:{','.join(missing)}"
            )

    return CheckPackEligibility(
        pack_id=pack.pack_id,
        version=pack.version,
        eligible=not reasons,
        reason_codes=tuple(sorted(reasons)),
    )


@dataclass(frozen=True)
class CheckCatalogEntry:
    pack_id: str
    name: str
    version: str
    check_count: int
    families: tuple[str, ...]
    tags: tuple[str, ...]
    supported_services: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    max_intrusiveness: str
    signer_key_id: str
    source_feed_id: str
    sha256: str
    eligible: bool
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class RedCheckCatalog:
    entries: tuple[CheckCatalogEntry, ...]

    def search(
        self,
        *,
        family: str | None = None,
        tag: str | None = None,
        service: str | None = None,
        eligible_only: bool = False,
    ) -> tuple[CheckCatalogEntry, ...]:
        matches = self.entries
        if family is not None:
            matches = tuple(item for item in matches if family in item.families)
        if tag is not None:
            matches = tuple(item for item in matches if tag in item.tags)
        if service is not None:
            matches = tuple(
                item for item in matches if service in item.supported_services
            )
        if eligible_only:
            matches = tuple(item for item in matches if item.eligible)
        return matches


def build_check_catalog(
    artifacts: tuple[VerifiedEcosystemPack, ...],
    policy: CheckEcosystemPolicy,
) -> RedCheckCatalog:
    keys = [(item.pack.pack_id, item.pack.version) for item in artifacts]
    if len(keys) != len(set(keys)):
        raise ValueError("ecosystem catalog contains duplicate pack/version entries")

    entries: list[CheckCatalogEntry] = []
    for artifact in artifacts:
        pack = artifact.pack
        eligibility = evaluate_pack_eligibility(artifact, policy)
        intrusiveness = (
            max(
                (check.metadata.intrusiveness for check in pack.checks),
                key=lambda item: _ORDER[item],
            )
            if pack.checks else CheckIntrusiveness.PASSIVE
        )
        entries.append(CheckCatalogEntry(
            pack_id=pack.pack_id,
            name=pack.name,
            version=pack.version,
            check_count=len(pack.checks),
            families=tuple(sorted({c.metadata.family for c in pack.checks})),
            tags=tuple(sorted({
                tag for c in pack.checks for tag in c.metadata.tags
            })),
            supported_services=tuple(sorted({
                service
                for c in pack.checks
                for service in c.metadata.supported_services
            })),
            required_capabilities=tuple(sorted({
                capability
                for c in pack.checks
                for capability in c.metadata.required_capabilities
            })),
            max_intrusiveness=intrusiveness.value,
            signer_key_id=artifact.provenance.signer_key_id,
            source_feed_id=artifact.provenance.source_feed_id,
            sha256=artifact.provenance.sha256.lower(),
            eligible=eligibility.eligible,
            reason_codes=eligibility.reason_codes,
        ))

    return RedCheckCatalog(tuple(sorted(
        entries, key=lambda item: (item.pack_id, item.version)
    )))
