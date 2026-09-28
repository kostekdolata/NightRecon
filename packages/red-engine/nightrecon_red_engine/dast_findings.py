"""Structured non-secret findings for NightRecon DAST."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_red_engine.dast_evidence import (
    DastRetestDescriptor,
)


@dataclass(frozen=True)
class DastFinding:
    """One deterministic safe-active DAST finding."""

    check_id: str
    title: str
    severity: str
    target_url: str
    summary: str
    evidence: tuple[str, ...] = ()
    remediation: str = ""
    retest: DastRetestDescriptor | None = None
