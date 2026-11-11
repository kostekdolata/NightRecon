"""Deterministic operator report for offline Amass/httpx evidence correlation.

Reports observations and limitations; never upgrades imported data into findings.
"""
from __future__ import annotations

import hashlib
import json

from .amass_httpx_offline_correlation import correlate_amass_httpx


def build_offline_web_operator_report(
    amass_payload: bytes, httpx_payload: bytes, *,
    allowed_hosts: tuple[str, ...], allowed_urls: tuple[str, ...],
    engagement_id: str, max_links: int = 4096,
) -> dict:
    """Produce a bounded, stable, machine-readable review artifact.

    The engagement identifier is a label, not authorization. Every source
    is validated again against explicit scope by the correlation importer.
    """
    if (not isinstance(engagement_id, str)
            or not 1 <= len(engagement_id) <= 128
            or not all(c.isascii() and (c.isalnum() or c in "-_.") for c in engagement_id)):
        raise ValueError("Invalid engagement identifier")
    correlated = correlate_amass_httpx(
        amass_payload, httpx_payload,
        allowed_hosts=allowed_hosts, allowed_urls=allowed_urls,
        max_links=max_links,
    )
    evidence = correlated["links"]
    report = {
        "schema": "red.offline_web_operator_report.v1",
        "engagement_id": engagement_id,
        "status": "unverified_offline_evidence",
        "authorization": "not_established_by_import",
        "sources": correlated["sources"],
        "summary": {
            "amass_observations": correlated["sources"]["amass"]["record_count"],
            "httpx_observations": correlated["sources"]["httpx"]["record_count"],
            "correlated_associations": len(evidence),
            "confirmed_findings": 0,
        },
        "associations": evidence,
        "review": {
            "required": True,
            "next_step": "Review scope, source provenance and independent authorized validation before any finding or retest.",
            "limitations": correlated["limitations"],
        },
    }
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return {
        **report,
        "report_sha256": hashlib.sha256(canonical).hexdigest(),
    }
