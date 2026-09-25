"""Passive web assessment checks for NightRecon crawl metadata."""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit

from nightrecon.web_crawl import CrawlPage


@dataclass(frozen=True)
class WebAssessmentFinding:
    """One deterministic passive web-assessment finding."""

    check_id: str
    title: str
    severity: str
    page_url: str
    evidence: str


@dataclass(frozen=True)
class WebAssessmentSummary:
    """Descriptive summary of passive web-assessment findings."""

    total_findings: int
    high_count: int
    medium_count: int
    low_count: int
    unknown_count: int


def assess_web_pages(
    pages: tuple[CrawlPage, ...],
) -> tuple[WebAssessmentFinding, ...]:
    """Run deterministic passive checks over captured crawl metadata."""

    findings: list[WebAssessmentFinding] = []

    for page in pages:
        if page.error:
            continue

        page_scheme = urlsplit(
            page.url
        ).scheme.lower()

        for form in page.forms:
            has_password = any(
                field.input_type == "password"
                for field in form.inputs
            )

            if not has_password:
                continue

            if page_scheme == "http":
                findings.append(
                    WebAssessmentFinding(
                        check_id=(
                            "web.password-form-over-http"
                        ),
                        title=(
                            "Password form observed on "
                            "plaintext HTTP page"
                        ),
                        severity="medium",
                        page_url=page.url,
                        evidence=(
                            f"form action={form.action or '-'} "
                            f"method={form.method} contains "
                            "password input"
                        ),
                    )
                )

            if form.method.upper() == "GET":
                findings.append(
                    WebAssessmentFinding(
                        check_id=(
                            "web.password-form-uses-get"
                        ),
                        title=(
                            "Password form uses GET submission"
                        ),
                        severity="medium",
                        page_url=page.url,
                        evidence=(
                            f"form action={form.action or '-'} "
                            "method=GET contains password input"
                        ),
                    )
                )

        if page_scheme == "https":
            for source in page.script_sources:
                if (
                    urlsplit(source).scheme.lower()
                    == "http"
                ):
                    findings.append(
                        WebAssessmentFinding(
                            check_id=(
                                "web.mixed-content-script"
                            ),
                            title=(
                                "HTTPS page references "
                                "plaintext HTTP script"
                            ),
                            severity="medium",
                            page_url=page.url,
                            evidence=(
                                f"script source={source}"
                            ),
                        )
                    )

    return tuple(findings)


def summarize_web_assessments(
    findings: tuple[
        WebAssessmentFinding,
        ...,
    ],
) -> WebAssessmentSummary:
    """Summarize passive web findings without exploitability claims."""

    counts = {
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0,
    }

    for finding in findings:
        severity = finding.severity.lower()

        if severity in counts:
            counts[severity] += 1
        else:
            counts["unknown"] += 1

    return WebAssessmentSummary(
        total_findings=len(findings),
        high_count=counts["high"],
        medium_count=counts["medium"],
        low_count=counts["low"],
        unknown_count=counts["unknown"],
    )
