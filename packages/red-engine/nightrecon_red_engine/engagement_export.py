"""Versioned deterministic export for Red Night professional reports."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from nightrecon_red_engine.engagement_report import EngagementProfessionalReport


REPORT_EXPORT_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class EngagementReportExport:
    schema_version: int
    report: EngagementProfessionalReport
    fingerprint_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "report": self.report.to_dict(),
            "fingerprint_sha256": self.fingerprint_sha256,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
        )


def _canonical_payload(report: EngagementProfessionalReport) -> bytes:
    return json.dumps(
        {
            "schema_version": REPORT_EXPORT_SCHEMA_VERSION,
            "report": report.to_dict(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def build_engagement_report_export(
    report: EngagementProfessionalReport,
) -> EngagementReportExport:
    digest = hashlib.sha256(_canonical_payload(report)).hexdigest()
    return EngagementReportExport(
        schema_version=REPORT_EXPORT_SCHEMA_VERSION,
        report=report,
        fingerprint_sha256=digest,
    )


def write_engagement_report_export(
    report: EngagementProfessionalReport,
    path: str | Path,
) -> EngagementReportExport:
    export = build_engagement_report_export(report)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(export.to_json() + "\n", encoding="utf-8")
    return export
