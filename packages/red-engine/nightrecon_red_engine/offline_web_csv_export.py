"""Deterministic, bounded CSV review export of validated offline web evidence.

Exports only allowlisted columns; no third-party text or formulas are copied.
"""
from __future__ import annotations

import csv
import io

from .offline_web_evidence_delta import OfflineWebRetestError, _validate


class OfflineWebCsvExportError(ValueError):
    """Invalid report or unsafe CSV export request."""


def export_offline_web_report_csv(report: dict, *, max_associations: int = 4096) -> bytes:
    """Export reviewable associations without claiming verified findings.

    CSV rows contain only validated URL/host/status and independently checked
    source/report hashes. Imported source fields are never exported.
    """
    if type(max_associations) is not int or not 0 < max_associations <= 10000:
        raise OfflineWebCsvExportError("Invalid export budget")
    try:
        engagement_id, associations = _validate(report, max_associations)
    except (OfflineWebRetestError, TypeError, ValueError) as exc:
        raise OfflineWebCsvExportError("Invalid report or provenance") from exc
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow((
        "engagement_id", "host", "url", "http_status", "classification",
        "report_sha256", "amass_sha256", "httpx_sha256",
        "authorization", "confirmed_findings",
    ))
    for host, url, status in sorted(associations):
        # Host and URL are validated in the report, but guard CSV consumers
        # independently against spreadsheet formulas and control characters.
        if any(ord(c) < 32 or ord(c) == 127 for c in host + url):
            raise OfflineWebCsvExportError("Control characters in evidence")
        if any(value.lstrip().startswith(("=", "+", "-", "@")) for value in (host, url)):
            raise OfflineWebCsvExportError("Formula-like evidence")
        writer.writerow((
            engagement_id, host, url, status,
            "unverified_cross_tool_association",
            report["report_sha256"], report["sources"]["amass"]["sha256"],
            report["sources"]["httpx"]["sha256"],
            "not_established_by_import", 0,
        ))
    encoded = output.getvalue().encode("utf-8")
    if len(encoded) > 2_000_000:
        raise OfflineWebCsvExportError("Export exceeds size budget")
    return encoded
