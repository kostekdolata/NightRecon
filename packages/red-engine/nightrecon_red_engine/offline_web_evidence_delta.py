"""Offline operator retest comparison for unverified Amass/httpx reports.

No network operations, vulnerability verdicts, or authorization inferred.
"""
from __future__ import annotations

import hashlib
import json


class OfflineWebRetestError(ValueError):
    """Invalid, oversized, or incompatible operator reports."""


def _validate(report: dict, max_associations: int) -> tuple[str, set[tuple[str, str, int]]]:
    if not isinstance(report, dict):
        raise OfflineWebRetestError("Invalid report")
    raw = dict(report)
    digest = raw.pop("report_sha256", None)
    try:
        canonical = json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    except (TypeError, ValueError, OverflowError) as exc:
        raise OfflineWebRetestError("Unserializable report") from exc
    if (len(canonical) > 2_000_000 or not isinstance(digest, str)
            or hashlib.sha256(canonical).hexdigest() != digest):
        raise OfflineWebRetestError("Report digest mismatch or size exceeded")
    if (report.get("schema") != "red.offline_web_operator_report.v1"
            or report.get("status") != "unverified_offline_evidence"
            or report.get("authorization") != "not_established_by_import"
            or not isinstance(report.get("engagement_id"), str)
            or not report["engagement_id"]
            or not isinstance(report.get("associations"), list)
            or len(report["associations"]) > max_associations
            or not isinstance(report.get("sources"), dict)
            or not isinstance(report.get("summary"), dict)
            or report["summary"].get("confirmed_findings") != 0
            or report["summary"].get("correlated_associations") != len(report["associations"])):
        raise OfflineWebRetestError("Incompatible or invalid report")
    for source in ("amass", "httpx"):
        item = report["sources"].get(source)
        if (not isinstance(item, dict) or not isinstance(item.get("sha256"), str)
                or len(item["sha256"]) != 64
                or any(c not in "0123456789abcdef" for c in item["sha256"])
                or type(item.get("record_count")) is not int
                or not 0 <= item["record_count"] <= 10000):
            raise OfflineWebRetestError("Invalid source provenance")
    associations = set()
    for item in report["associations"]:
        if (not isinstance(item, dict)
                or item.get("classification") != "unverified_cross_tool_association"
                or item.get("source_amass_sha256") != report["sources"]["amass"]["sha256"]
                or item.get("source_httpx_sha256") != report["sources"]["httpx"]["sha256"]
                or not isinstance(item.get("host"), str)
                or not isinstance(item.get("url"), str)
                or type(item.get("http_status")) is not int
                or not 100 <= item["http_status"] <= 599):
            raise OfflineWebRetestError("Invalid association")
        from urllib.parse import urlsplit
        try:
            parsed = urlsplit(item["url"])
            host_matches = (parsed.scheme in ("http", "https")
                            and parsed.hostname == item["host"]
                            and not parsed.username and not parsed.password
                            and not parsed.fragment)
        except ValueError as exc:
            raise OfflineWebRetestError("Invalid association URL") from exc
        if not host_matches:
            raise OfflineWebRetestError("Association host mismatch")
        associations.add((item["host"], item["url"], item["http_status"]))
    if len(associations) != len(report["associations"]):
        raise OfflineWebRetestError("Duplicate associations")
    return report["engagement_id"], associations


def compare_offline_web_reports(before: dict, after: dict, *,
                                max_associations: int = 4096) -> dict:
    """Compare two review snapshots, not remediation or live retest outcomes."""
    if type(max_associations) is not int or not 0 < max_associations <= 10000:
        raise OfflineWebRetestError("Invalid comparison budget")
    engagement_before, old = _validate(before, max_associations)
    engagement_after, new = _validate(after, max_associations)
    if engagement_before != engagement_after:
        raise OfflineWebRetestError("Cross-engagement comparison forbidden")

    def rows(items):
        return [{"host": h, "url": u, "http_status": s}
                for h, u, s in sorted(items)]

    return {
        "schema": "red.offline_web_evidence_delta.v1",
        "engagement_id": engagement_before,
        "authority": "untrusted_offline_import",
        "before_report_sha256": before["report_sha256"],
        "after_report_sha256": after["report_sha256"],
        "added_observations": rows(new - old),
        "removed_observations": rows(old - new),
        "unchanged_count": len(old & new),
        "confirmed_findings": 0,
        "remediation_verified": False,
        "limitations": (
            "Offline observation differences are not evidence of vulnerability "
            "remediation, target reachability, or an authorized live retest."
        ),
    }
