"""Offline fixture-quality benchmark for review grouping; no target or tool execution."""
from __future__ import annotations

from .static_evidence_operator_review import StaticReviewError


def benchmark_static_review(review: dict, *, expected_positive_ids: frozenset[str],
                            expected_negative_ids: frozenset[str],
                            max_groups: int = 10000) -> dict:
    """Compare review groups to explicitly labeled synthetic truth, without inventing labels.

    Unknown predictions are not counted as false positives; precision is withheld
    while any predicted group is unlabeled. This is fixture coverage, not tool parity.
    """
    if type(max_groups) is not int or not 0 < max_groups <= 100000:
        raise StaticReviewError("Invalid benchmark budget")
    if not isinstance(review, dict) or review.get("schema") != "red.static_evidence_review.v1":
        raise StaticReviewError("Validated static review required")
    if review.get("authority") != "review_only_not_authorization" or review.get("cross_tool_correlations") != []:
        raise StaticReviewError("Unsupported authority or correlation")
    groups = review.get("review_groups")
    if not isinstance(groups, list) or len(groups) > max_groups:
        raise StaticReviewError("Invalid group budget")
    if type(review.get("review_group_count")) is not int or review["review_group_count"] != len(groups):
        raise StaticReviewError("Inconsistent group count")
    if type(review.get("observation_count")) is not int or review["observation_count"] < 0:
        raise StaticReviewError("Invalid observation total")
    if type(expected_positive_ids) is not frozenset or type(expected_negative_ids) is not frozenset:
        raise StaticReviewError("Explicit immutable fixture labels required")
    labels = expected_positive_ids | expected_negative_ids
    if expected_positive_ids & expected_negative_ids or not labels:
        raise StaticReviewError("Conflicting or absent fixture labels")
    def valid_id(value: object) -> bool:
        return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
    if any(not valid_id(x) for x in labels):
        raise StaticReviewError("Invalid fixture identity")
    observed = set()
    count = 0
    for group in groups:
        if not isinstance(group, dict) or group.get("source_tool") not in ("Trivy", "Semgrep"):
            raise StaticReviewError("Invalid group")
        if group.get("status") != "needs_operator_review" or group.get("exploitability") != "not_established":
            raise StaticReviewError("Unsupported evidence conclusion")
        identifier = group.get("review_id")
        amount = group.get("observation_count")
        if not valid_id(identifier) or identifier in observed or type(amount) is not int or amount <= 0:
            raise StaticReviewError("Invalid review identity or count")
        observed.add(identifier)
        count += amount
    if count != review["observation_count"]:
        raise StaticReviewError("Inconsistent observation count")
    tp = len(observed & expected_positive_ids)
    fp = len(observed & expected_negative_ids)
    fn = len(expected_positive_ids - observed)
    unknown = len(observed - labels)
    return {
        "schema": "red.offline_review_fixture_benchmark.v1",
        "true_positive": tp, "false_positive": fp, "false_negative": fn,
        "unlabeled_predictions": unknown,
        "precision": tp / (tp + fp) if tp + fp and not unknown else None,
        "recall": tp / (tp + fn) if tp + fn else None,
        "scope": "synthetic_fixture_only",
        "limitations": "Review-group matching only; no detection efficacy, exploitability, real-world parity or authorization established",
        "authority": "benchmark_only_not_authorization",
    }
