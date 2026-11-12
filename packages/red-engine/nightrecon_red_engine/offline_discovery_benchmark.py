"""No-network fixture quality accounting for Amass DNS and httpx evidence."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from .amass_offline_evidence import import_amass_jsonl
from .httpx_offline_evidence import import_httpx_jsonl


class DiscoveryBenchmarkError(ValueError):
    """Invalid reviewed fixture labels."""


def compare_offline_discovery(*, amass_payload: bytes, httpx_payload: bytes,
                              approved_domain: str, approved_origins: tuple[str, ...],
                              labels: Mapping[str, Mapping[str, str]]) -> dict:
    """Compare synthetic reviewed labels, never claim live detection parity."""
    dns = import_amass_jsonl(amass_payload, approved_domain=approved_domain)
    web = import_httpx_jsonl(httpx_payload, approved_origins=approved_origins)
    sources = {"amass": dns, "httpx": web}
    if not isinstance(labels, Mapping) or set(labels) != set(sources):
        raise DiscoveryBenchmarkError("Both tool label maps are required")
    summary = {}
    for tool, imported in sources.items():
        reviewed = labels[tool]
        if not isinstance(reviewed, Mapping) or len(reviewed) > 2000:
            raise DiscoveryBenchmarkError("Invalid label budget")
        for identity, disposition in reviewed.items():
            if (not isinstance(identity, str) or len(identity) != 64 or
                any(c not in "0123456789abcdef" for c in identity) or
                disposition not in ("expected", "known_negative")):
                raise DiscoveryBenchmarkError("Invalid reviewed label")
        observed = {row["observation_id"] for row in imported["observations"]}
        positive = {k for k, v in reviewed.items() if v == "expected"}
        negative = {k for k, v in reviewed.items() if v == "known_negative"}
        tp, fp, fn = len(observed & positive), len(observed & negative), len(positive - observed)
        unknown = len(observed - positive - negative)
        summary[tool] = {
            "true_positive": tp, "false_positive": fp, "false_negative": fn,
            "unlabeled": unknown,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "source_report_sha256": imported["source_report_sha256"],
        }
    fingerprint = hashlib.sha256(json.dumps(summary, sort_keys=True,
                                           separators=(",", ":")).encode()).hexdigest()
    return {
        "schema": "red.offline_discovery_fixture_benchmark.v1",
        "results": summary, "fingerprint": fingerprint,
        "authority": "evidence_only_not_authorization",
        "limitations": "Synthetic offline importer matching only; no probing or specialist parity",
    }
