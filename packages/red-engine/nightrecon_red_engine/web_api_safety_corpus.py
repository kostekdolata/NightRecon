"""Deterministic no-network safety regression corpus for Red Night web/API policy.

The corpus exercises policy decisions only. It does not send requests and does
not claim Burp/ZAP parity, exploitability, or vulnerability coverage.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json

from nightrecon_red_engine.api_policy import (
    ApiRequest,
    ApiRequestPolicy,
    ApiRequestState,
    authorize_api_request,
)
from nightrecon_red_engine.browser_policy import (
    BrowserDiscoveryPolicy,
    BrowserRequest,
    BrowserResourceKind,
    BrowserWorkerState,
    authorize_browser_request,
)

WEB_API_SAFETY_CORPUS_INTERPRETATION = (
    "This deterministic corpus verifies NightRecon web/API authorization and "
    "request-safety policy decisions only. It is not a Burp/ZAP parity claim, "
    "a vulnerability verdict, or evidence of exploitability."
)


@dataclass(frozen=True)
class WebApiSafetyCaseResult:
    surface: str
    name: str
    expected_allowed: bool
    actual_allowed: bool
    expected_reason: str
    actual_reason: str

    @property
    def matched(self) -> bool:
        return (
            self.expected_allowed == self.actual_allowed
            and self.expected_reason == self.actual_reason
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "surface": self.surface,
            "name": self.name,
            "expected_allowed": self.expected_allowed,
            "actual_allowed": self.actual_allowed,
            "expected_reason": self.expected_reason,
            "actual_reason": self.actual_reason,
            "matched": self.matched,
        }


@dataclass(frozen=True)
class WebApiSafetyCorpusResult:
    total_cases: int
    matched_cases: int
    unexpected_cases: int
    cases: tuple[WebApiSafetyCaseResult, ...]
    fingerprint: str
    interpretation: str = WEB_API_SAFETY_CORPUS_INTERPRETATION

    @property
    def passed(self) -> bool:
        return self.unexpected_cases == 0

    def to_dict(self) -> dict[str, object]:
        return {
            "total_cases": self.total_cases,
            "matched_cases": self.matched_cases,
            "unexpected_cases": self.unexpected_cases,
            "passed": self.passed,
            "cases": [item.to_dict() for item in self.cases],
            "fingerprint": self.fingerprint,
            "interpretation": self.interpretation,
        }


def _fingerprint(cases: tuple[WebApiSafetyCaseResult, ...]) -> str:
    payload = json.dumps(
        [item.to_dict() for item in cases],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def run_web_api_safety_corpus(
    *,
    origin: str = "https://example.test",
) -> WebApiSafetyCorpusResult:
    """Run the fixed policy-only regression corpus."""

    browser_policy = BrowserDiscoveryPolicy(
        origin=origin,
        max_requests=2,
        max_pages=2,
        max_runtime_seconds=5.0,
    )
    browser_state = BrowserWorkerState(
        requests_used=0,
        pages_used=0,
        runtime_seconds=0.0,
        max_requests=2,
        max_pages=2,
        max_runtime_seconds=5.0,
    )
    api_policy = ApiRequestPolicy(origin=origin, max_requests=2)
    api_state = ApiRequestState(requests_used=0, max_requests=2)

    results: list[WebApiSafetyCaseResult] = []

    browser_cases = (
        ("same-origin-get", f"{origin}/app", "GET", True, "authorized"),
        ("mutating-post", f"{origin}/update", "POST", False, "method_not_allowed"),
        (
            "cross-origin-get",
            "https://outside.invalid/app",
            "GET",
            False,
            "outside_authorized_origin",
        ),
    )
    for name, url, method, allowed, reason in browser_cases:
        decision = authorize_browser_request(
            request=BrowserRequest(
                url=url,
                method=method,
                resource_kind=BrowserResourceKind.DOCUMENT,
            ),
            policy=browser_policy,
            state=browser_state,
        )
        results.append(
            WebApiSafetyCaseResult(
                surface="browser",
                name=name,
                expected_allowed=allowed,
                actual_allowed=decision.allowed,
                expected_reason=reason,
                actual_reason=decision.reason,
            )
        )

    api_cases = (
        ("same-origin-get", f"{origin}/api/status", "GET", True, "authorized"),
        ("mutating-post", f"{origin}/api/update", "POST", False, "method_not_allowed"),
        (
            "cross-origin-get",
            "https://outside.invalid/api/status",
            "GET",
            False,
            "outside_authorized_origin",
        ),
    )
    for name, url, method, allowed, reason in api_cases:
        decision = authorize_api_request(
            request=ApiRequest(url=url, method=method, operation_id=name),
            policy=api_policy,
            state=api_state,
        )
        results.append(
            WebApiSafetyCaseResult(
                surface="api",
                name=name,
                expected_allowed=allowed,
                actual_allowed=decision.allowed,
                expected_reason=reason,
                actual_reason=decision.reason,
            )
        )

    exhausted_browser = BrowserWorkerState(
        requests_used=2,
        pages_used=0,
        runtime_seconds=0.0,
        max_requests=2,
        max_pages=2,
        max_runtime_seconds=5.0,
    )
    browser_budget = authorize_browser_request(
        request=BrowserRequest(
            url=f"{origin}/later",
            method="GET",
            resource_kind=BrowserResourceKind.DOCUMENT,
        ),
        policy=browser_policy,
        state=exhausted_browser,
    )
    results.append(
        WebApiSafetyCaseResult(
            surface="browser",
            name="request-budget-exhausted",
            expected_allowed=False,
            actual_allowed=browser_budget.allowed,
            expected_reason="request_budget_exhausted",
            actual_reason=browser_budget.reason,
        )
    )

    exhausted_api = ApiRequestState(requests_used=2, max_requests=2)
    api_budget = authorize_api_request(
        request=ApiRequest(
            url=f"{origin}/api/later",
            method="GET",
            operation_id="budget",
        ),
        policy=api_policy,
        state=exhausted_api,
    )
    results.append(
        WebApiSafetyCaseResult(
            surface="api",
            name="request-budget-exhausted",
            expected_allowed=False,
            actual_allowed=api_budget.allowed,
            expected_reason="request_budget_exhausted",
            actual_reason=api_budget.reason,
        )
    )

    cases = tuple(results)
    matched = sum(item.matched for item in cases)
    return WebApiSafetyCorpusResult(
        total_cases=len(cases),
        matched_cases=matched,
        unexpected_cases=len(cases) - matched,
        cases=cases,
        fingerprint=_fingerprint(cases),
    )
