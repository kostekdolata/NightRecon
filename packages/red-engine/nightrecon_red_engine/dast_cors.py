"""Bounded credentialed-CORS reflection validation for NightRecon."""

from __future__ import annotations

from dataclasses import dataclass
from http.cookiejar import CookieJar

from nightrecon_red_engine.dast_evidence import (
    DastEvidenceRecord,
    build_dast_evidence,
    build_retest_descriptor,
    redact_dast_url,
)
from nightrecon_red_engine.dast_findings import DastFinding
from nightrecon_red_engine.dast_http import (
    DastHttpResult,
    execute_dast_http_request,
)
from nightrecon_red_engine.dast_policy import (
    DastBudgetPolicy,
    DastBudgetState,
    DastCheckDefinition,
)
from nightrecon_red_engine.web_crawl import (
    normalize_http_url,
    url_origin,
)


_SYNTHETIC_ORIGIN = "https://nightrecon.invalid"
_CORS_CHECK = DastCheckDefinition(
    check_id="web.cors.credentialed-origin-reflection",
    name="Credentialed CORS Origin Reflection",
    family="cors",
    description=(
        "Compares a baseline OPTIONS response with a bounded preflight "
        "using a fixed synthetic origin and reports only explicit origin "
        "reflection together with credential allowance."
    ),
    max_requests=10,
    allowed_methods=("OPTIONS",),
    tags=(
        "web",
        "cors",
        "headers",
        "safe-active",
    ),
)


@dataclass(frozen=True)
class DastCorsAssessmentResult:
    """Outcome of bounded credentialed-CORS reflection checks."""

    findings: tuple[DastFinding, ...]
    evidence_records: tuple[DastEvidenceRecord, ...]
    state: DastBudgetState
    targets_attempted: int
    requests_attempted: int
    errors: tuple[str, ...] = ()


def _header(
    result: DastHttpResult,
    name: str,
) -> str:
    return dict(
        result.response_headers
    ).get(
        name.lower(),
        "",
    ).strip()


def assess_credentialed_cors(
    *,
    urls: tuple[str, ...],
    origin: str,
    policy: DastBudgetPolicy,
    state: DastBudgetState,
    authorized: bool,
    max_targets: int = 3,
    timeout: float = 5.0,
    max_response_bytes: int = 65_536,
    authorization: str | None = None,
    cookie_jar: CookieJar | None = None,
) -> DastCorsAssessmentResult:
    """Check explicit credentialed reflection of NightRecon's synthetic origin."""

    if not authorized:
        raise PermissionError(
            "Credentialed CORS assessment requires explicit authorization."
        )

    if max_targets < 1:
        raise ValueError(
            "max_targets must be at least 1."
        )

    if (
        max_targets
        * 2
        > _CORS_CHECK.max_requests
    ):
        raise ValueError(
            "max_targets exceeds the check request ceiling."
        )

    normalized_origin = url_origin(
        origin
    )
    candidates: list[
        str
    ] = []
    seen: set[
        str
    ] = set()
    errors: list[
        str
    ] = []

    for raw_url in urls:
        try:
            candidate = normalize_http_url(
                raw_url
            )
        except ValueError:
            errors.append(
                "invalid_target_url"
            )
            continue

        if url_origin(
            candidate
        ) != normalized_origin:
            errors.append(
                "outside_authorized_origin"
            )
            continue

        if candidate in seen:
            continue

        seen.add(
            candidate
        )
        candidates.append(
            candidate
        )

        if len(
            candidates
        ) >= max_targets:
            break

    current_state = state
    initial_total = (
        state.total_used
    )
    findings: list[
        DastFinding
    ] = []
    evidence_records: list[
        DastEvidenceRecord
    ] = []

    for candidate in candidates:
        try:
            baseline = execute_dast_http_request(
                check=_CORS_CHECK,
                url=candidate,
                method="OPTIONS",
                origin=normalized_origin,
                policy=policy,
                state=current_state,
                authorized=True,
                timeout=timeout,
                max_response_bytes=max_response_bytes,
                authorization=authorization,
                cookie_jar=cookie_jar,
            )
        except PermissionError:
            errors.append(
                "baseline_request_not_authorized"
            )
            break

        current_state = (
            baseline.state
        )

        try:
            probe = execute_dast_http_request(
                check=_CORS_CHECK,
                url=candidate,
                method="OPTIONS",
                origin=normalized_origin,
                policy=policy,
                state=current_state,
                authorized=True,
                timeout=timeout,
                max_response_bytes=max_response_bytes,
                synthetic_headers=(
                    (
                        "Origin",
                        _SYNTHETIC_ORIGIN,
                    ),
                    (
                        "Access-Control-Request-Method",
                        "GET",
                    ),
                ),
                authorization=authorization,
                cookie_jar=cookie_jar,
            )
        except PermissionError:
            errors.append(
                "probe_request_not_authorized"
            )
            break

        current_state = (
            probe.state
        )

        if (
            not baseline.success
            or not probe.success
            or baseline.fingerprint
            is None
            or probe.fingerprint
            is None
        ):
            errors.append(
                "incomplete_cors_response_pair"
            )
            continue

        evidence = build_dast_evidence(
            check=_CORS_CHECK,
            target_url=candidate,
            method="OPTIONS",
            request_ordinal=(
                current_state.total_used
            ),
            baseline=baseline.fingerprint,
            candidate=probe.fingerprint,
        )
        evidence_records.append(
            evidence
        )

        allow_origin = _header(
            probe,
            "access-control-allow-origin",
        )
        allow_credentials = _header(
            probe,
            "access-control-allow-credentials",
        ).lower()

        if not (
            allow_origin
            == _SYNTHETIC_ORIGIN
            and allow_credentials
            == "true"
        ):
            continue

        baseline_allow_origin = _header(
            baseline,
            "access-control-allow-origin",
        )
        retest = build_retest_descriptor(
            evidence
        )
        findings.append(
            DastFinding(
                check_id=_CORS_CHECK.check_id,
                title=(
                    "Credentialed CORS policy reflected "
                    "NightRecon synthetic origin"
                ),
                severity="medium",
                target_url=redact_dast_url(
                    candidate
                ),
                summary=(
                    "A bounded preflight response explicitly allowed "
                    "NightRecon's fixed synthetic origin together with "
                    "credentialed cross-origin requests. This is a "
                    "configuration observation; practical impact depends "
                    "on browser credential behavior and whether sensitive "
                    "responses are accessible."
                ),
                evidence=(
                    (
                        "synthetic_origin_reflected="
                        f"{_SYNTHETIC_ORIGIN}"
                    ),
                    (
                        "access_control_allow_credentials=true"
                    ),
                    (
                        "baseline_allow_origin="
                        f"{baseline_allow_origin or '-'}"
                    ),
                    (
                        "response_difference_material="
                        f"{'yes' if evidence.difference.material_difference else 'no'}"
                    ),
                ),
                remediation=(
                    "Restrict credentialed CORS to explicitly trusted "
                    "origins, avoid reflecting arbitrary Origin values, "
                    "and retest sensitive endpoints after policy changes."
                ),
                retest=retest,
            )
        )

    return DastCorsAssessmentResult(
        findings=tuple(
            findings
        ),
        evidence_records=tuple(
            evidence_records
        ),
        state=current_state,
        targets_attempted=len(
            candidates
        ),
        requests_attempted=(
            current_state.total_used
            - initial_total
        ),
        errors=tuple(
            errors
        ),
    )
