"""Deterministic redacted operator handoff from bounded offline review evidence.

No scanning, file writes, authority changes, or exploitability promotion.
"""
from __future__ import annotations

import hashlib
import json

from .static_evidence_operator_review import StaticReviewError


def build_operator_handoff(review: dict, *, max_groups: int = 10000) -> dict:
    """Summarize an offline review without exposing targets, paths, or rule IDs."""
    if type(max_groups) is not int or not 0 < max_groups <= 100000:
        raise StaticReviewError("Invalid handoff budget")
    if not isinstance(review, dict) or review.get("schema") != "red.static_evidence_review.v1":
        raise StaticReviewError("Static review required")
    if review.get("authority") != "review_only_not_authorization":
        raise StaticReviewError("Review authority marker required")
    if review.get("cross_tool_correlations") != []:
        raise StaticReviewError("Unsupported cross-tool correlations")
    groups = review.get("review_groups")
    sources = review.get("sources")
    if not isinstance(groups, list) or len(groups) > max_groups or not isinstance(sources, list):
        raise StaticReviewError("Invalid handoff inputs")
    if len(sources) != 2 or [s.get("tool") for s in sources if isinstance(s, dict)] != ["Trivy", "Semgrep"]:
        raise StaticReviewError("Expected tool sources required")
    for source in sources:
        digest = source.get("digest")
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise StaticReviewError("Invalid source digest")
    if type(review.get("review_group_count")) is not int or review["review_group_count"] != len(groups):
        raise StaticReviewError("Inconsistent group count")
    counts = {"Trivy": 0, "Semgrep": 0}
    observed = 0
    ids = set()
    for group in groups:
        if not isinstance(group, dict) or group.get("source_tool") not in counts:
            raise StaticReviewError("Invalid review group")
        if group.get("status") != "needs_operator_review" or group.get("exploitability") != "not_established":
            raise StaticReviewError("Unsupported evidence conclusion")
        identifier = group.get("review_id")
        if not isinstance(identifier, str) or len(identifier) != 64 or any(c not in "0123456789abcdef" for c in identifier) or identifier in ids:
            raise StaticReviewError("Invalid review identifier")
        ids.add(identifier)
        count = group.get("observation_count")
        if type(count) is not int or count <= 0:
            raise StaticReviewError("Invalid observation count")
        observed += count
        counts[group["source_tool"]] += 1
    if type(review.get("observation_count")) is not int or review["observation_count"] != observed:
        raise StaticReviewError("Inconsistent observation total")
    # Digest is a reproducibility checksum, not a signature or evidence authentication.
    canonical = json.dumps(
        {"source_digests": [s["digest"] for s in sources], "review_ids": sorted(ids), "observations": observed},
        sort_keys=True, separators=(",", ":"),
    )
    return {
        "schema": "red.operator_handoff.v1",
        "review_checksum_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "checksum_meaning": "reproducibility_only_not_authentication",
        "observations": observed,
        "review_groups": len(groups),
        "groups_by_tool": counts,
        "review_required": len(groups),
        "confirmed_exploitable": None,
        "remediation_verified": None,
        "retest_verified": None,
        "operator_next_steps": [
            "Verify source provenance and approved engagement scope independently",
            "Review each source-specific observation and obtain corroborating evidence",
            "Record remediation ownership and evidence before any retest claim",
            "Perform retesting only through separately authorized governed workflows",
        ],
        "limitations": "Offline third-party observations only; no execution, cross-tool correlation, exploitability, remediation or retest verified",
        "authority": "report_only_not_authorization",
    }
