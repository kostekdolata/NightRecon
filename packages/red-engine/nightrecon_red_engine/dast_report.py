"""Structured non-secret reporting for NightRecon safe-active DAST."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from nightrecon_red_engine.dast_evidence import (
    DastEvidenceRecord,
)
from nightrecon_red_engine.dast_findings import DastFinding
from nightrecon_red_engine.dast_policy import (
    DastBudgetPolicy,
    DastBudgetState,
)
from nightrecon_red_engine.session import ScanSession


@dataclass(frozen=True)
class DastAssessmentReport:
    """One bounded safe-active DAST run."""

    session_id: str
    created_at: str
    target: str
    target_type: str
    scope: tuple[str, ...]
    status: str
    origin: str
    enabled_checks: tuple[str, ...]
    max_total_requests: int
    default_family_requests: int
    family_limits: tuple[
        tuple[str, int],
        ...,
    ]
    requests_used: int
    check_usage: tuple[
        tuple[str, int],
        ...,
    ]
    family_usage: tuple[
        tuple[str, int],
        ...,
    ]
    findings: tuple[DastFinding, ...]
    evidence_records: tuple[
        DastEvidenceRecord,
        ...,
    ]
    errors: tuple[str, ...]

    @classmethod
    def create(
        cls,
        *,
        session: ScanSession,
        origin: str,
        enabled_checks: tuple[str, ...],
        policy: DastBudgetPolicy,
        state: DastBudgetState,
        findings: tuple[DastFinding, ...],
        evidence_records: tuple[DastEvidenceRecord, ...],
        errors: tuple[str, ...] = (),
    ) -> "DastAssessmentReport":
        return cls(
            session_id=session.session_id,
            created_at=session.created_at,
            target=session.target,
            target_type=session.target_type,
            scope=session.scope,
            status="completed",
            origin=origin,
            enabled_checks=tuple(
                sorted(
                    set(
                        enabled_checks
                    )
                )
            ),
            max_total_requests=(
                policy.max_total_requests
            ),
            default_family_requests=(
                policy.default_family_requests
            ),
            family_limits=(
                policy.family_limits
            ),
            requests_used=state.total_used,
            check_usage=state.check_usage,
            family_usage=state.family_usage,
            findings=findings,
            evidence_records=evidence_records,
            errors=errors,
        )

    def to_dict(self) -> dict:
        data = asdict(
            self
        )
        severity_counts: dict[
            str,
            int,
        ] = {}

        for finding in self.findings:
            severity = (
                finding.severity.strip().lower()
                or "unknown"
            )
            severity_counts[
                severity
            ] = (
                severity_counts.get(
                    severity,
                    0,
                )
                + 1
            )

        data["summary"] = {
            "enabled_checks": len(
                self.enabled_checks
            ),
            "requests_used": (
                self.requests_used
            ),
            "findings": len(
                self.findings
            ),
            "evidence_records": len(
                self.evidence_records
            ),
            "errors": len(
                self.errors
            ),
            "severity_counts": dict(
                sorted(
                    severity_counts.items()
                )
            ),
        }
        return data
