"""Declarative assessment check packs for NightRecon."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

from nightrecon.assessment_engine import (
    AssessmentCheckMetadata,
    AssessmentContext,
    AssessmentFinding,
    CheckIntrusiveness,
)


CHECK_PACK_SCHEMA_VERSION = 1

_SUPPORTED_FIELDS = {
    "target",
    "address",
    "port",
    "service",
    "banner",
    "http_status",
    "http_server",
    "http_headers",
    "security_headers_present",
    "security_headers_missing",
    "tls_version",
    "tls_cipher",
    "tls_certificate_subject",
    "tls_certificate_issuer",
    "tls_certificate_not_before",
    "tls_certificate_not_after",
    "tls_certificate_sans",
    "tls_certificate_sha256",
    "software.product",
    "software.version",
    "software.source",
    "software.evidence",
}

_SUPPORTED_OPERATORS = {
    "equals",
    "not_equals",
    "contains",
    "not_contains",
    "present",
    "missing",
    "starts_with",
    "ends_with",
    "in",
}


@dataclass(frozen=True)
class DeclarativeCondition:
    """Safe condition evaluated against whitelisted observed fields."""

    field: str
    operator: str
    value: object | None = None


@dataclass(frozen=True)
class DeclarativeFindingTemplate:
    """Static finding content emitted when all conditions match."""

    title: str
    summary: str
    severity: str = ""
    remediation: str = ""
    references: tuple[str, ...] = ()


@dataclass(frozen=True)
class DeclarativeAssessmentCheck:
    """Assessment check backed entirely by declarative observations."""

    metadata: AssessmentCheckMetadata
    conditions: tuple[DeclarativeCondition, ...]
    finding: DeclarativeFindingTemplate
    evidence_fields: tuple[str, ...] = ()

    def run(
        self,
        context: AssessmentContext,
    ) -> tuple[AssessmentFinding, ...]:
        """Evaluate all conditions without arbitrary code execution."""

        if not all(
            _condition_matches(
                condition,
                context,
            )
            for condition in self.conditions
        ):
            return ()

        evidence = tuple(
            _format_evidence(
                field,
                _resolve_field(
                    field,
                    context,
                ),
            )
            for field in self.evidence_fields
        )

        return (
            AssessmentFinding(
                check_id=self.metadata.check_id,
                title=self.finding.title,
                summary=self.finding.summary,
                evidence=evidence,
                severity=self.finding.severity,
                remediation=self.finding.remediation,
                references=self.finding.references,
            ),
        )


@dataclass(frozen=True)
class CheckPack:
    """Validated declarative assessment-check pack."""

    schema_version: int
    pack_id: str
    name: str
    version: str
    checks: tuple[DeclarativeAssessmentCheck, ...] = ()


def load_check_pack_json(
    text: str,
) -> CheckPack:
    """Parse and validate one JSON declarative check pack."""

    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"Invalid check-pack JSON: {exc.msg}"
        ) from exc

    return load_check_pack_payload(payload)


def load_check_pack_payload(
    payload: object,
) -> CheckPack:
    """Validate a decoded check-pack payload."""

    if not isinstance(payload, dict):
        raise ValueError(
            "Check-pack payload must be a JSON object."
        )

    schema_version = payload.get("schema_version")

    if schema_version != CHECK_PACK_SCHEMA_VERSION:
        raise ValueError(
            "Unsupported check-pack schema version: "
            f"{schema_version!r}"
        )

    pack_id = _required_text(
        payload,
        "pack_id",
    )
    name = _required_text(
        payload,
        "name",
    )
    version = _required_text(
        payload,
        "version",
    )

    raw_checks = payload.get("checks", [])

    if not isinstance(raw_checks, list):
        raise ValueError(
            "Check-pack checks must be a list."
        )

    checks = tuple(
        _parse_check(item)
        for item in raw_checks
    )

    check_ids = [
        check.metadata.check_id
        for check in checks
    ]

    if len(check_ids) != len(set(check_ids)):
        raise ValueError(
            "Duplicate check_id in check pack."
        )

    return CheckPack(
        schema_version=schema_version,
        pack_id=pack_id,
        name=name,
        version=version,
        checks=checks,
    )


def _parse_check(
    item: object,
) -> DeclarativeAssessmentCheck:
    if not isinstance(item, dict):
        raise ValueError(
            "Each declarative check must be an object."
        )

    intrusiveness_text = _required_text(
        item,
        "intrusiveness",
    )

    try:
        intrusiveness = CheckIntrusiveness(
            intrusiveness_text
        )
    except ValueError as exc:
        raise ValueError(
            "Unsupported check intrusiveness: "
            f"{intrusiveness_text}"
        ) from exc

    raw_conditions = item.get(
        "conditions",
        [],
    )

    if not isinstance(raw_conditions, list):
        raise ValueError(
            "Check conditions must be a list."
        )

    conditions = tuple(
        _parse_condition(condition)
        for condition in raw_conditions
    )

    raw_finding = item.get("finding")

    if not isinstance(raw_finding, dict):
        raise ValueError(
            "Check finding must be an object."
        )

    finding = DeclarativeFindingTemplate(
        title=_required_text(
            raw_finding,
            "title",
        ),
        summary=_required_text(
            raw_finding,
            "summary",
        ),
        severity=_optional_text(
            raw_finding.get("severity")
        ),
        remediation=_optional_text(
            raw_finding.get("remediation")
        ),
        references=_string_tuple(
            raw_finding.get(
                "references",
                [],
            ),
            "finding references",
        ),
    )

    evidence_fields = _string_tuple(
        item.get(
            "evidence_fields",
            [],
        ),
        "evidence_fields",
    )

    for field in evidence_fields:
        _validate_field(field)

    return DeclarativeAssessmentCheck(
        metadata=AssessmentCheckMetadata(
            check_id=_required_text(
                item,
                "check_id",
            ),
            name=_required_text(
                item,
                "name",
            ),
            family=_required_text(
                item,
                "family",
            ),
            description=_required_text(
                item,
                "description",
            ),
            intrusiveness=intrusiveness,
            supported_services=_string_tuple(
                item.get(
                    "supported_services",
                    [],
                ),
                "supported_services",
            ),
            tags=_string_tuple(
                item.get(
                    "tags",
                    [],
                ),
                "tags",
            ),
            requires_authentication=bool(
                item.get(
                    "requires_authentication",
                    False,
                )
            ),
            required_capabilities=_string_tuple(
                item.get(
                    "required_capabilities",
                    [],
                ),
                "required_capabilities",
            ),
            version=_optional_text(
                item.get("version")
            )
            or "1",
        ),
        conditions=conditions,
        finding=finding,
        evidence_fields=evidence_fields,
    )


def _parse_condition(
    item: object,
) -> DeclarativeCondition:
    if not isinstance(item, dict):
        raise ValueError(
            "Each declarative condition must be an object."
        )

    field = _required_text(
        item,
        "field",
    )
    operator = _required_text(
        item,
        "operator",
    )

    _validate_field(field)

    if operator not in _SUPPORTED_OPERATORS:
        raise ValueError(
            "Unsupported declarative operator: "
            f"{operator}"
        )

    return DeclarativeCondition(
        field=field,
        operator=operator,
        value=item.get("value"),
    )


def _validate_field(
    field: str,
) -> None:
    if field not in _SUPPORTED_FIELDS:
        raise ValueError(
            "Unsupported declarative field: "
            f"{field}"
        )


def _condition_matches(
    condition: DeclarativeCondition,
    context: AssessmentContext,
) -> bool:
    observed = _resolve_field(
        condition.field,
        context,
    )
    expected = condition.value
    operator = condition.operator

    if operator == "present":
        return _is_present(observed)

    if operator == "missing":
        return not _is_present(observed)

    if operator == "equals":
        return observed == expected

    if operator == "not_equals":
        return observed != expected

    if operator == "contains":
        return _contains(
            observed,
            expected,
        )

    if operator == "not_contains":
        return not _contains(
            observed,
            expected,
        )

    if operator == "starts_with":
        return (
            isinstance(observed, str)
            and isinstance(expected, str)
            and observed.startswith(expected)
        )

    if operator == "ends_with":
        return (
            isinstance(observed, str)
            and isinstance(expected, str)
            and observed.endswith(expected)
        )

    if operator == "in":
        return (
            isinstance(expected, (list, tuple))
            and observed in expected
        )

    return False


def _resolve_field(
    field: str,
    context: AssessmentContext,
) -> object:
    if field == "target":
        return context.target

    if field == "address":
        return context.address

    if field == "port":
        return context.port

    if field == "service":
        return context.service

    service = context.service_result

    if field.startswith("software."):
        software = getattr(
            service,
            "software_identity",
            None,
        )

        if software is None:
            return None

        software_field = field.split(
            ".",
            1,
        )[1]

        return {
            "product": getattr(
                software,
                "product",
                None,
            ),
            "version": getattr(
                software,
                "version",
                None,
            ),
            "source": getattr(
                software,
                "source",
                None,
            ),
            "evidence": getattr(
                software,
                "evidence",
                None,
            ),
        }[software_field]

    attribute_map = {
        "banner": "banner",
        "http_status": "http_status",
        "http_server": "http_server",
        "http_headers": "http_headers",
        "security_headers_present": (
            "security_headers_present"
        ),
        "security_headers_missing": (
            "security_headers_missing"
        ),
        "tls_version": "tls_version",
        "tls_cipher": "tls_cipher",
        "tls_certificate_subject": (
            "tls_certificate_subject"
        ),
        "tls_certificate_issuer": (
            "tls_certificate_issuer"
        ),
        "tls_certificate_not_before": (
            "tls_certificate_not_before"
        ),
        "tls_certificate_not_after": (
            "tls_certificate_not_after"
        ),
        "tls_certificate_sans": (
            "tls_certificate_sans"
        ),
        "tls_certificate_sha256": (
            "tls_certificate_sha256"
        ),
    }

    return getattr(
        service,
        attribute_map[field],
        None,
    )


def _contains(
    observed: object,
    expected: object,
) -> bool:
    if isinstance(observed, str):
        return (
            isinstance(expected, str)
            and expected in observed
        )

    if isinstance(
        observed,
        (tuple, list, set),
    ):
        return expected in observed

    return False


def _is_present(
    value: object,
) -> bool:
    if value is None:
        return False

    if isinstance(value, str):
        return bool(value.strip())

    if isinstance(
        value,
        (tuple, list, set, dict),
    ):
        return bool(value)

    return True


def _format_evidence(
    field: str,
    value: object,
) -> str:
    if isinstance(value, (tuple, list)):
        rendered = ",".join(
            str(item)
            for item in value
        )
    else:
        rendered = str(value)

    return f"{field}={rendered}"


def _required_text(
    payload: dict[str, Any],
    key: str,
) -> str:
    value = payload.get(key)

    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            f"{key} must be a non-empty string."
        )

    return value.strip()


def _optional_text(
    value: object,
) -> str:
    if isinstance(value, str):
        return value.strip()

    return ""


def _string_tuple(
    value: object,
    label: str,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(
            f"{label} must be a list."
        )

    result: list[str] = []

    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(
                f"{label} entries must be non-empty strings."
            )

        result.append(item.strip())

    return tuple(result)
