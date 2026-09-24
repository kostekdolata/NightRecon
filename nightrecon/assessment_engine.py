"""Extensible assessment-check engine for NightRecon."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class CheckIntrusiveness(str, Enum):
    """Declared operational impact of an assessment check."""

    PASSIVE = "passive"
    SAFE_ACTIVE = "safe-active"
    INTRUSIVE = "intrusive"
    DESTRUCTIVE = "destructive"


_INTRUSIVENESS_ORDER = {
    CheckIntrusiveness.PASSIVE: 0,
    CheckIntrusiveness.SAFE_ACTIVE: 1,
    CheckIntrusiveness.INTRUSIVE: 2,
    CheckIntrusiveness.DESTRUCTIVE: 3,
}


@dataclass(frozen=True)
class AssessmentCheckMetadata:
    """Static metadata describing one assessment check."""

    check_id: str
    name: str
    family: str
    description: str
    intrusiveness: CheckIntrusiveness
    supported_services: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    requires_authentication: bool = False
    required_capabilities: tuple[str, ...] = ()
    version: str = "1"

    def __post_init__(self) -> None:
        if not self.check_id.strip():
            raise ValueError("check_id must not be empty.")

        if not self.name.strip():
            raise ValueError("name must not be empty.")

        if not self.family.strip():
            raise ValueError("family must not be empty.")


@dataclass(frozen=True)
class AssessmentContext:
    """Authorized target/service context supplied to a check."""

    target: str
    address: str
    port: int
    service: str
    authorized: bool
    authenticated: bool = False
    capabilities: tuple[str, ...] = ()
    service_result: object | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.port <= 65535:
            raise ValueError(
                "port must be between 1 and 65535."
            )


@dataclass(frozen=True)
class AssessmentFinding:
    """Structured evidence returned by an assessment check."""

    check_id: str
    title: str
    summary: str
    evidence: tuple[str, ...] = ()
    severity: str = ""
    remediation: str = ""
    references: tuple[str, ...] = ()


@dataclass(frozen=True)
class AssessmentExecutionResult:
    """Outcome from running or evaluating one assessment check."""

    check_id: str
    status: str
    findings: tuple[AssessmentFinding, ...] = ()
    reason: str = ""
    error: str = ""


@dataclass(frozen=True)
class ServiceAssessmentResult:
    """Assessment executions bound to one detected network service."""

    address: str
    port: int
    service: str
    executions: tuple[AssessmentExecutionResult, ...] = ()


@dataclass(frozen=True)
class AssessmentSummary:
    """Descriptive summary of assessment execution outcomes."""

    services_assessed: int
    checks_completed: int
    checks_skipped: int
    checks_errored: int
    findings: int


def assess_services(
    *,
    target: str,
    services: tuple[object, ...],
    checks: tuple[AssessmentCheck, ...],
    max_intrusiveness: CheckIntrusiveness = (
        CheckIntrusiveness.SAFE_ACTIVE
    ),
    authorized: bool,
) -> tuple[ServiceAssessmentResult, ...]:
    """Run assessment checks against detected services."""

    engine = AssessmentEngine(
        max_intrusiveness=max_intrusiveness
    )
    results: list[ServiceAssessmentResult] = []

    ordered_services = sorted(
        services,
        key=lambda service: (
            service.address,
            service.port,
            service.service,
        ),
    )

    for service in ordered_services:
        executions = engine.run(
            checks=checks,
            context=AssessmentContext(
                target=target,
                address=service.address,
                port=service.port,
                service=service.service,
                authorized=authorized,
                service_result=service,
            ),
        )

        results.append(
            ServiceAssessmentResult(
                address=service.address,
                port=service.port,
                service=service.service,
                executions=executions,
            )
        )

    return tuple(results)


def summarize_assessments(
    results: tuple[ServiceAssessmentResult, ...],
) -> AssessmentSummary:
    """Return descriptive counts for service assessment results."""

    completed = 0
    skipped = 0
    errored = 0
    findings = 0

    for service_result in results:
        for execution in service_result.executions:
            if execution.status == "completed":
                completed += 1
            elif execution.status == "skipped":
                skipped += 1
            elif execution.status == "error":
                errored += 1

            findings += len(execution.findings)

    return AssessmentSummary(
        services_assessed=len(results),
        checks_completed=completed,
        checks_skipped=skipped,
        checks_errored=errored,
        findings=findings,
    )


class AssessmentCheck(Protocol):
    """Protocol implemented by NightRecon assessment checks."""

    metadata: AssessmentCheckMetadata

    def run(
        self,
        context: AssessmentContext,
    ) -> tuple[AssessmentFinding, ...]:
        """Execute the check in an already-authorized context."""


class CheckRegistry:
    """Deterministic registry for installed assessment checks."""

    def __init__(self) -> None:
        self._checks: dict[str, AssessmentCheck] = {}

    def register(
        self,
        check: AssessmentCheck,
    ) -> None:
        check_id = check.metadata.check_id

        if check_id in self._checks:
            raise ValueError(
                f"Duplicate assessment check id: {check_id}"
            )

        self._checks[check_id] = check

    def get(
        self,
        check_id: str,
    ) -> AssessmentCheck:
        return self._checks[check_id]

    def all(
        self,
    ) -> tuple[AssessmentCheck, ...]:
        return tuple(
            self._checks[check_id]
            for check_id in sorted(self._checks)
        )

    def select(
        self,
        *,
        check_ids: tuple[str, ...] = (),
        families: tuple[str, ...] = (),
        tags: tuple[str, ...] = (),
    ) -> tuple[AssessmentCheck, ...]:
        """Select installed checks using deterministic metadata filters."""

        check_id_filter = set(check_ids)
        family_filter = set(families)
        tag_filter = set(tags)

        selected: list[AssessmentCheck] = []

        for check in self.all():
            metadata = check.metadata

            if (
                check_id_filter
                and metadata.check_id not in check_id_filter
            ):
                continue

            if (
                family_filter
                and metadata.family not in family_filter
            ):
                continue

            if (
                tag_filter
                and not tag_filter.intersection(metadata.tags)
            ):
                continue

            selected.append(check)

        return tuple(selected)


class AssessmentEngine:
    """Execute assessment checks under an explicit safety ceiling."""

    def __init__(
        self,
        *,
        max_intrusiveness: CheckIntrusiveness = (
            CheckIntrusiveness.SAFE_ACTIVE
        ),
    ) -> None:
        self.max_intrusiveness = max_intrusiveness

    def run(
        self,
        *,
        checks: tuple[AssessmentCheck, ...],
        context: AssessmentContext,
    ) -> tuple[AssessmentExecutionResult, ...]:
        """Run checks in stable order against an authorized service."""

        if not context.authorized:
            raise PermissionError(
                "Assessment context is not authorized."
            )

        ordered_checks = tuple(
            sorted(
                checks,
                key=lambda check: check.metadata.check_id,
            )
        )

        results: list[AssessmentExecutionResult] = []

        for check in ordered_checks:
            metadata = check.metadata

            if not self._intrusiveness_allowed(
                metadata.intrusiveness
            ):
                results.append(
                    AssessmentExecutionResult(
                        check_id=metadata.check_id,
                        status="skipped",
                        reason="intrusiveness_not_allowed",
                    )
                )
                continue

            if (
                metadata.supported_services
                and context.service
                not in metadata.supported_services
            ):
                results.append(
                    AssessmentExecutionResult(
                        check_id=metadata.check_id,
                        status="skipped",
                        reason="service_not_supported",
                    )
                )
                continue

            if metadata.requires_authentication and not context.authenticated:
                results.append(
                    AssessmentExecutionResult(
                        check_id=metadata.check_id,
                        status="skipped",
                        reason="authentication_required",
                    )
                )
                continue

            if (
                metadata.required_capabilities
                and not set(
                    metadata.required_capabilities
                ).issubset(
                    set(context.capabilities)
                )
            ):
                results.append(
                    AssessmentExecutionResult(
                        check_id=metadata.check_id,
                        status="skipped",
                        reason="required_capability_unavailable",
                    )
                )
                continue

            try:
                findings = tuple(
                    check.run(context)
                )
            except Exception as exc:
                results.append(
                    AssessmentExecutionResult(
                        check_id=metadata.check_id,
                        status="error",
                        error=(
                            str(exc)
                            or exc.__class__.__name__
                        ),
                    )
                )
                continue

            results.append(
                AssessmentExecutionResult(
                    check_id=metadata.check_id,
                    status="completed",
                    findings=findings,
                )
            )

        return tuple(results)

    def _intrusiveness_allowed(
        self,
        intrusiveness: CheckIntrusiveness,
    ) -> bool:
        return (
            _INTRUSIVENESS_ORDER[intrusiveness]
            <= _INTRUSIVENESS_ORDER[
                self.max_intrusiveness
            ]
        )
