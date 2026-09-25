"""Structured web-crawl reports for NightRecon."""

from __future__ import annotations

from dataclasses import asdict, dataclass

from nightrecon.session import ScanSession
from nightrecon.web_assessment import (
    WebAssessmentFinding,
    summarize_web_assessments,
)
from nightrecon.web_crawl import CrawlPage, CrawlResult


@dataclass(frozen=True)
class WebCrawlReport:
    """Complete result of one bounded authorized web crawl."""

    session_id: str
    created_at: str
    target: str
    target_type: str
    scope: tuple[str, ...]
    status: str
    start_url: str
    origin: str
    max_pages: int
    max_bytes_per_page: int
    pages: tuple[CrawlPage, ...]
    assessment_enabled: bool = False
    assessment_intrusiveness: str = "disabled"
    assessment_findings: tuple[
        WebAssessmentFinding,
        ...,
    ] = ()
    safe_active_requests_attempted: int = 0
    safe_active_successful_probes: int = 0
    safe_active_errors: tuple[str, ...] = ()

    @classmethod
    def create(
        cls,
        *,
        session: ScanSession,
        crawl: CrawlResult,
        assessment_enabled: bool = False,
        assessment_intrusiveness: str = "disabled",
        assessment_findings: tuple[
            WebAssessmentFinding,
            ...,
        ] = (),
        safe_active_requests_attempted: int = 0,
        safe_active_successful_probes: int = 0,
        safe_active_errors: tuple[str, ...] = (),
    ) -> "WebCrawlReport":
        return cls(
            session_id=session.session_id,
            created_at=session.created_at,
            target=session.target,
            target_type=session.target_type,
            scope=session.scope,
            status="completed",
            start_url=crawl.start_url,
            origin=crawl.origin,
            max_pages=crawl.max_pages,
            max_bytes_per_page=crawl.max_bytes_per_page,
            pages=crawl.pages,
            assessment_enabled=assessment_enabled,
            assessment_intrusiveness=assessment_intrusiveness,
            assessment_findings=assessment_findings,
            safe_active_requests_attempted=(
                safe_active_requests_attempted
            ),
            safe_active_successful_probes=(
                safe_active_successful_probes
            ),
            safe_active_errors=safe_active_errors,
        )

    @property
    def successful_pages(self) -> tuple[CrawlPage, ...]:
        return tuple(
            page
            for page in self.pages
            if not page.error
        )

    @property
    def failed_pages(self) -> tuple[CrawlPage, ...]:
        return tuple(
            page
            for page in self.pages
            if page.error
        )

    def to_dict(self) -> dict:
        data = asdict(self)
        data["pages"] = [
            asdict(page)
            for page in self.pages
        ]
        data["summary"] = {
            "pages_fetched": len(self.pages),
            "successful_pages": len(self.successful_pages),
            "failed_pages": len(self.failed_pages),
            "links_observed": sum(
                len(page.links)
                for page in self.pages
            ),
            "forms_observed": sum(
                len(page.forms)
                for page in self.pages
            ),
            "script_sources_observed": sum(
                len(page.script_sources)
                for page in self.pages
            ),
        }
        data["assessment_summary"] = (
            asdict(
                summarize_web_assessments(
                    self.assessment_findings
                )
            )
            if self.assessment_enabled
            else None
        )
        data["safe_active_summary"] = (
            {
                "requests_attempted": (
                    self.safe_active_requests_attempted
                ),
                "successful_probes": (
                    self.safe_active_successful_probes
                ),
                "errors": len(
                    self.safe_active_errors
                ),
            }
            if (
                self.assessment_enabled
                and self.assessment_intrusiveness == "safe-active"
            )
            else None
        )
        return data
