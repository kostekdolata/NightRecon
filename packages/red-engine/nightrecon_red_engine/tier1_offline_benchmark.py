"""Deterministic offline benchmark quality gate for synthetic Tier 1 observations.

Labels are explicitly synthetic ground truth, never real vulnerability verdicts.
No tool execution, network I/O, or authorization inference.
"""
from __future__ import annotations

import hashlib
import json
import re

from .tier1_capability_plan import TIER1


class OfflineBenchmarkError(ValueError):
    """Malformed or out-of-scope synthetic benchmark input."""


def score_synthetic_tier1_benchmark(
    payload: bytes, *, engagement_id: str, authorized_targets: tuple[str, ...],
    max_bytes: int = 262144, max_cases: int = 2048,
) -> dict:
    """Score TP/FP/TN/FN per tool against explicitly labeled synthetic cases."""
    if (not isinstance(payload, bytes) or type(max_bytes) is not int
            or not 0 < max_bytes <= 1048576 or not 0 < len(payload) <= max_bytes
            or type(max_cases) is not int or not 0 < max_cases <= 4096
            or not isinstance(engagement_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", engagement_id) is None
            or not isinstance(authorized_targets, tuple)
            or not 0 < len(authorized_targets) <= 256
            or any(not isinstance(t, str) or not 0 < len(t) <= 2048
                   or t != t.strip() or "\\" in t
                   or any(ord(c) < 33 for c in t) for t in authorized_targets)
            or len(set(authorized_targets)) != len(authorized_targets)):
        raise OfflineBenchmarkError("Invalid engagement, scope or resource budget")
    try:
        data = json.loads(payload)
    except (ValueError, UnicodeDecodeError) as exc:
        raise OfflineBenchmarkError("Invalid benchmark JSON") from exc
    if (not isinstance(data, dict) or set(data) != {"schema", "synthetic", "cases"}
            or data["schema"] != "red.synthetic_tier1_benchmark_fixture.v1"
            or data["synthetic"] is not True or not isinstance(data["cases"], list)
            or not 0 < len(data["cases"]) <= max_cases):
        raise OfflineBenchmarkError("Invalid synthetic benchmark envelope")
    scope = set(authorized_targets)
    counts = {}
    seen = set()
    for row in data["cases"]:
        if not isinstance(row, dict) or set(row) != {
            "case_id", "tool", "target", "expected_positive", "observed_positive"
        }:
            raise OfflineBenchmarkError("Invalid benchmark case")
        case_id, tool, target = row["case_id"], row["tool"], row["target"]
        if (not isinstance(case_id, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", case_id) is None
                or not isinstance(tool, str) or tool not in TIER1
                or not isinstance(target, str) or target not in scope
                or type(row["expected_positive"]) is not bool
                or type(row["observed_positive"]) is not bool
                or case_id in seen):
            raise OfflineBenchmarkError("Invalid, duplicate or out-of-scope case")
        seen.add(case_id)
        stats = counts.setdefault(tool, {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
        expected, observed = row["expected_positive"], row["observed_positive"]
        key = ("tp" if expected else "fp") if observed else ("fn" if expected else "tn")
        stats[key] += 1
    by_tool = []
    for tool in sorted(counts):
        c = counts[tool]
        positives = c["tp"] + c["fp"]
        actual = c["tp"] + c["fn"]
        negatives = c["fp"] + c["tn"]
        by_tool.append({
            "tool": tool, **c, "case_count": sum(c.values()),
            "precision": c["tp"] / positives if positives else None,
            "recall": c["tp"] / actual if actual else None,
            "false_positive_rate": c["fp"] / negatives if negatives else None,
        })
    return {
        "schema": "red.synthetic_tier1_benchmark_score.v1",
        "engagement_id": engagement_id, "fixture_sha256": hashlib.sha256(payload).hexdigest(),
        "synthetic": True, "external_execution": False, "integration_verified": False,
        "case_count": len(seen), "by_tool": by_tool,
        "limitations": (
            "Synthetic labeled cases only; scores do not establish live tool quality, "
            "authorization, real-world detection, or vulnerability exploitability. "
            "Null rates mean the required denominator was absent."
        ),
    }
