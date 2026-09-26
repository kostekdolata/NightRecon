"""Structured non-secret reporting for NightRecon browser discovery."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from nightrecon.browser_playwright import (
    BrowserFormObservation,
    BrowserPageObservation,
    PlaywrightDiscoveryResult,
)
from nightrecon.browser_policy import BrowserDiscoveryPolicy
from nightrecon.session import ScanSession


def _report_url(value: str) -> str:
    """Remove query/fragment data before persistence."""

    if not value:
        return ""

    parts = urlsplit(value)

    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            "",
            "",
        )
    )


def _safe_error(value: str | None) -> str | None:
    """Persist error class/code only, never raw browser exception text."""

    if value is None:
        return None

    if value in {
        "dom_byte_limit_exceeded",
        "response_byte_limit_exceeded",
    }:
        return value

    head = value.split(
        ":",
        1,
    )[0].strip()

    return (
        head[:128]
        if head
        else "browser_discovery_failed"
    )


@dataclass(frozen=True)
class BrowserReportField:
    name: str
    input_type: str


@dataclass(frozen=True)
class BrowserReportForm:
    action: str
    method: str
    inputs: tuple[BrowserReportField, ...]

    @classmethod
    def from_observation(
        cls,
        form: BrowserFormObservation,
    ) -> "BrowserReportForm":
        return cls(
            action=_report_url(
                form.action
            ),
            method=form.method,
            inputs=tuple(
                BrowserReportField(
                    name=item.name,
                    input_type=item.input_type,
                )
                for item in form.inputs
            ),
        )


@dataclass(frozen=True)
class BrowserReportPage:
    url: str
    title: str
    links: tuple[str, ...]
    forms: tuple[BrowserReportForm, ...]

    @classmethod
    def from_observation(
        cls,
        page: BrowserPageObservation,
    ) -> "BrowserReportPage":
        return cls(
            url=_report_url(
                page.url
            ),
            title=page.title,
            links=tuple(
                _report_url(link)
                for link in page.links
            ),
            forms=tuple(
                BrowserReportForm.from_observation(
                    form
                )
                for form in page.forms
            ),
        )


@dataclass(frozen=True)
class BrowserReportRequest:
    url: str
    method: str
    resource_kind: str
    allowed: bool
    reason: str


@dataclass(frozen=True)
class BrowserReportResponse:
    url: str
    status: int | None
    byte_count: int
    capture_allowed: bool
    reason: str


@dataclass(frozen=True)
class BrowserReportDom:
    url: str
    byte_count: int
    capture_allowed: bool
    reason: str


@dataclass(frozen=True)
class BrowserDiscoveryReport:
    session_id: str
    created_at: str
    target: str
    target_type: str
    scope: tuple[str, ...]
    status: str
    origin: str
    max_requests: int
    max_pages: int
    max_runtime_seconds: float
    max_response_bytes: int
    max_dom_bytes: int
    max_dom_items: int
    requests_used: int
    pages_used: int
    runtime_seconds: float
    page: BrowserReportPage | None
    requests: tuple[BrowserReportRequest, ...]
    responses: tuple[BrowserReportResponse, ...]
    dom_snapshots: tuple[BrowserReportDom, ...]
    error: str | None

    @classmethod
    def create(
        cls,
        *,
        session: ScanSession,
        policy: BrowserDiscoveryPolicy,
        result: PlaywrightDiscoveryResult,
    ) -> "BrowserDiscoveryReport":
        snapshot = result.snapshot

        return cls(
            session_id=session.session_id,
            created_at=datetime.now(
                timezone.utc
            ).isoformat(),
            target=session.target,
            target_type=session.target_type,
            scope=session.scope,
            status=(
                "completed"
                if result.error is None
                else "failed"
            ),
            origin=_report_url(
                policy.origin
            ),
            max_requests=policy.max_requests,
            max_pages=policy.max_pages,
            max_runtime_seconds=policy.max_runtime_seconds,
            max_response_bytes=policy.max_response_bytes,
            max_dom_bytes=policy.max_dom_bytes,
            max_dom_items=policy.max_dom_items,
            requests_used=snapshot.state.requests_used,
            pages_used=snapshot.state.pages_used,
            runtime_seconds=snapshot.state.runtime_seconds,
            page=(
                BrowserReportPage.from_observation(
                    result.page
                )
                if result.page is not None
                else None
            ),
            requests=tuple(
                BrowserReportRequest(
                    url=_report_url(
                        item.url
                    ),
                    method=item.method,
                    resource_kind=item.resource_kind.value,
                    allowed=item.allowed,
                    reason=item.reason,
                )
                for item in snapshot.requests
            ),
            responses=tuple(
                BrowserReportResponse(
                    url=_report_url(
                        item.url
                    ),
                    status=item.status,
                    byte_count=item.byte_count,
                    capture_allowed=item.capture_allowed,
                    reason=item.reason,
                )
                for item in snapshot.responses
            ),
            dom_snapshots=tuple(
                BrowserReportDom(
                    url=_report_url(
                        item.url
                    ),
                    byte_count=item.byte_count,
                    capture_allowed=item.capture_allowed,
                    reason=item.reason,
                )
                for item in snapshot.dom_snapshots
            ),
            error=_safe_error(
                result.error
            ),
        )

    def to_dict(self) -> dict:
        data = asdict(self)
        data["summary"] = {
            "requests_observed": len(
                self.requests
            ),
            "requests_allowed": sum(
                item.allowed
                for item in self.requests
            ),
            "requests_blocked": sum(
                not item.allowed
                for item in self.requests
            ),
            "responses_observed": len(
                self.responses
            ),
            "links_discovered": (
                len(self.page.links)
                if self.page is not None
                else 0
            ),
            "forms_observed": (
                len(self.page.forms)
                if self.page is not None
                else 0
            ),
        }
        return data
