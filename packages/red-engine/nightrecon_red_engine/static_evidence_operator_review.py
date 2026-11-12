"""Offline operator review of Trivy and Semgrep imports; never infers exploitability or shared identity."""
from __future__ import annotations

import hashlib
import json


class StaticReviewError(ValueError):
    """Input violates the bounded, untrusted evidence review contract."""


def build_static_review(trivy: dict, semgrep: dict, *, max_findings: int = 10000) -> dict:
    """Build deterministic review groups without executing tools or linking unrelated targets."""
    if type(max_findings) is not int or not 0 < max_findings <= 100000:
        raise StaticReviewError("Invalid review budget")
    if not isinstance(trivy, dict) or trivy.get("schema") != "red.trivy_offline_import.v1":
        raise StaticReviewError("Validated Trivy import required")
    if not isinstance(semgrep, dict) or semgrep.get("source_tool") != "Semgrep":
        raise StaticReviewError("Validated Semgrep import required")
    if trivy.get("authority") != "untrusted_offline_import_not_authorization" or semgrep.get("authority") != "untrusted_offline_import":
        raise StaticReviewError("Untrusted evidence authority marker required")
    if not isinstance(trivy.get("findings"), list) or not isinstance(semgrep.get("findings"), list):
        raise StaticReviewError("Findings arrays required")
    if len(trivy["findings"]) + len(semgrep["findings"]) > max_findings:
        raise StaticReviewError("Review budget exceeded")
    for digest in (trivy.get("payload_sha256"), semgrep.get("sha256")):
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise StaticReviewError("Source digest required")
    if trivy.get("finding_count") != len(trivy["findings"]) or semgrep.get("finding_count") != len(semgrep["findings"]):
        raise StaticReviewError("Inconsistent source counts")
    groups = {}
    for finding in trivy["findings"]:
        if not isinstance(finding, dict) or finding.get("classification") != "unverified_tool_observation":
            raise StaticReviewError("Invalid Trivy observation")
        target, identifier, package = (finding.get(k) for k in ("target", "vulnerability_id", "package"))
        if any(not isinstance(x, str) or not x or len(x) > 2048 for x in (target, identifier, package)):
            raise StaticReviewError("Invalid Trivy identity")
        key = ("Trivy", target, identifier, package)
        groups[key] = groups.get(key, 0) + 1
    source = semgrep.get("source_name")
    if not isinstance(source, str) or not source or len(source) > 256:
        raise StaticReviewError("Invalid Semgrep source")
    for finding in semgrep["findings"]:
        if not isinstance(finding, dict) or finding.get("classification") != "unverified_tool_observation":
            raise StaticReviewError("Invalid Semgrep observation")
        rule, paths = finding.get("rule_id"), finding.get("artifact_uris")
        if not isinstance(rule, str) or not rule or len(rule) > 512 or not isinstance(paths, list) or len(paths) > 100:
            raise StaticReviewError("Invalid Semgrep identity")
        if any(not isinstance(p, str) or len(p) > 4096 for p in paths):
            raise StaticReviewError("Invalid Semgrep artifact")
        # No path is treated as an approved target. Keep provenance source-scoped.
        for path in sorted(set(paths)) or [""]:
            key = ("Semgrep", source, rule, path)
            groups[key] = groups.get(key, 0) + 1
    review = []
    for (tool, source_scope, identifier, location), count in sorted(groups.items()):
        canonical = json.dumps([tool, source_scope, identifier, location], separators=(",", ":"), ensure_ascii=True)
        review.append({
            "review_id": hashlib.sha256(canonical.encode()).hexdigest(),
            "source_tool": tool,
            "source_scope": source_scope,
            "observation_id": identifier,
            "location": location,
            "observation_count": count,
            "status": "needs_operator_review",
            "exploitability": "not_established",
        })
    return {
        "schema": "red.static_evidence_review.v1",
        "sources": [
            {"tool": "Trivy", "digest": trivy["payload_sha256"]},
            {"tool": "Semgrep", "digest": semgrep["sha256"]},
        ],
        "observation_count": len(trivy["findings"]) + len(semgrep["findings"]),
        "review_group_count": len(review),
        "review_groups": review,
        "cross_tool_correlations": [],
        "limitations": "Source-specific observations only; no shared asset identity, authorization, exploitability, remediation or retest verified",
        "authority": "review_only_not_authorization",
    }
