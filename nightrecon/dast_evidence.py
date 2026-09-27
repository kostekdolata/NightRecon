"""Deterministic, non-secret DAST response evidence for NightRecon."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import urlsplit, urlunsplit


@dataclass(frozen=True)
class DastResponseFingerprint:
    """Bounded response metadata without retaining response bodies."""

    status: int | None
    content_type: str
    observed_byte_count: int
    sample_byte_count: int
    sample_sha256: str
    sample_truncated: bool

    def __post_init__(self) -> None:
        if self.observed_byte_count < 0:
            raise ValueError(
                "observed_byte_count cannot be negative."
            )

        if self.sample_byte_count < 0:
            raise ValueError(
                "sample_byte_count cannot be negative."
            )

        if self.sample_byte_count > self.observed_byte_count:
            raise ValueError(
                "sample_byte_count cannot exceed observed_byte_count."
            )


@dataclass(frozen=True)
class DastResponseDifference:
    """Descriptive difference signals between baseline and candidate responses."""

    status_changed: bool
    content_type_changed: bool
    significant_length_change: bool
    sample_changed: bool
    byte_count_delta: int
    relative_length_change: float
    strong_signals: tuple[str, ...]
    weak_signals: tuple[str, ...]
    material_difference: bool


@dataclass(frozen=True)
class DastEvidenceRecord:
    """Reproducible non-secret evidence for one DAST comparison."""

    check_id: str
    family: str
    target_url: str
    method: str
    request_ordinal: int
    baseline: DastResponseFingerprint
    candidate: DastResponseFingerprint
    difference: DastResponseDifference
    retest_id: str

    def __post_init__(self) -> None:
        if self.request_ordinal < 1:
            raise ValueError(
                "request_ordinal must be at least 1."
            )


@dataclass(frozen=True)
class DastRetestDescriptor:
    """Stable identity and expected signals for deterministic retesting."""

    retest_id: str
    check_id: str
    family: str
    target_url: str
    method: str
    expected_strong_signals: tuple[str, ...]


def redact_dast_url(
    url: str,
) -> str:
    """Drop userinfo, query, and fragment from persisted DAST URLs."""

    parts = urlsplit(
        url.strip()
    )

    if parts.scheme not in {
        "http",
        "https",
    } or not parts.hostname:
        raise ValueError(
            "DAST URL must be an absolute HTTP(S) URL."
        )

    hostname = parts.hostname
    port = (
        f":{parts.port}"
        if parts.port is not None
        else ""
    )

    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"

    return urlunsplit(
        (
            parts.scheme.lower(),
            f"{hostname}{port}",
            parts.path or "/",
            "",
            "",
        )
    )


def fingerprint_response(
    *,
    status: int | None,
    content_type: str,
    observed_byte_count: int,
    body_sample: bytes,
    max_sample_bytes: int = 8192,
) -> DastResponseFingerprint:
    """Create a bounded response fingerprint without storing response bytes."""

    if observed_byte_count < 0:
        raise ValueError(
            "observed_byte_count cannot be negative."
        )

    if max_sample_bytes < 1:
        raise ValueError(
            "max_sample_bytes must be at least 1."
        )

    if not isinstance(
        body_sample,
        bytes,
    ):
        raise ValueError(
            "body_sample must be bytes."
        )

    bounded = body_sample[
        :max_sample_bytes
    ]

    if len(bounded) > observed_byte_count:
        bounded = bounded[
            :observed_byte_count
        ]

    return DastResponseFingerprint(
        status=status,
        content_type=content_type.strip().lower(),
        observed_byte_count=observed_byte_count,
        sample_byte_count=len(
            bounded
        ),
        sample_sha256=sha256(
            bounded
        ).hexdigest(),
        sample_truncated=(
            observed_byte_count
            > len(bounded)
        ),
    )


def compare_response_fingerprints(
    baseline: DastResponseFingerprint,
    candidate: DastResponseFingerprint,
    *,
    min_length_delta: int = 32,
    min_relative_length_change: float = 0.10,
) -> DastResponseDifference:
    """Compare fingerprints using conservative strong/weak difference signals."""

    if min_length_delta < 0:
        raise ValueError(
            "min_length_delta cannot be negative."
        )

    if not 0 <= min_relative_length_change <= 1:
        raise ValueError(
            "min_relative_length_change must be between 0 and 1."
        )

    byte_count_delta = (
        candidate.observed_byte_count
        - baseline.observed_byte_count
    )
    absolute_delta = abs(
        byte_count_delta
    )
    denominator = max(
        baseline.observed_byte_count,
        candidate.observed_byte_count,
        1,
    )
    relative_change = (
        absolute_delta
        / denominator
    )

    status_changed = (
        baseline.status
        != candidate.status
    )
    content_type_changed = (
        baseline.content_type
        != candidate.content_type
    )
    significant_length_change = (
        absolute_delta
        >= min_length_delta
        and relative_change
        >= min_relative_length_change
    )
    sample_changed = (
        baseline.sample_sha256
        != candidate.sample_sha256
    )

    strong_signals: list[
        str
    ] = []
    weak_signals: list[
        str
    ] = []

    if status_changed:
        strong_signals.append(
            "status_changed"
        )

    if content_type_changed:
        strong_signals.append(
            "content_type_changed"
        )

    if significant_length_change:
        strong_signals.append(
            "significant_length_change"
        )

    if sample_changed:
        if strong_signals:
            strong_signals.append(
                "sample_changed"
            )
        else:
            weak_signals.append(
                "sample_changed"
            )

    return DastResponseDifference(
        status_changed=status_changed,
        content_type_changed=content_type_changed,
        significant_length_change=significant_length_change,
        sample_changed=sample_changed,
        byte_count_delta=byte_count_delta,
        relative_length_change=round(
            relative_change,
            6,
        ),
        strong_signals=tuple(
            strong_signals
        ),
        weak_signals=tuple(
            weak_signals
        ),
        material_difference=bool(
            strong_signals
        ),
    )


def _retest_id(
    *,
    check_id: str,
    family: str,
    target_url: str,
    method: str,
) -> str:
    identity = (
        f"{check_id}\n"
        f"{family}\n"
        f"{method}\n"
        f"{target_url}"
    ).encode(
        "utf-8"
    )

    return sha256(
        identity
    ).hexdigest()


def build_dast_evidence(
    *,
    check: DastCheckDefinition,
    target_url: str,
    method: str,
    request_ordinal: int,
    baseline: DastResponseFingerprint,
    candidate: DastResponseFingerprint,
    min_length_delta: int = 32,
    min_relative_length_change: float = 0.10,
) -> DastEvidenceRecord:
    """Build one deterministic evidence record from two fingerprints."""

    normalized_method = method.strip().upper()

    if normalized_method not in check.allowed_methods:
        raise PermissionError(
            "Evidence method is not allowed by the DAST check."
        )

    redacted_url = redact_dast_url(
        target_url
    )
    difference = compare_response_fingerprints(
        baseline,
        candidate,
        min_length_delta=min_length_delta,
        min_relative_length_change=min_relative_length_change,
    )

    return DastEvidenceRecord(
        check_id=check.check_id,
        family=check.family,
        target_url=redacted_url,
        method=normalized_method,
        request_ordinal=request_ordinal,
        baseline=baseline,
        candidate=candidate,
        difference=difference,
        retest_id=_retest_id(
            check_id=check.check_id,
            family=check.family,
            target_url=redacted_url,
            method=normalized_method,
        ),
    )


def build_retest_descriptor(
    evidence: DastEvidenceRecord,
) -> DastRetestDescriptor:
    """Create stable non-secret metadata for a later retest."""

    return DastRetestDescriptor(
        retest_id=evidence.retest_id,
        check_id=evidence.check_id,
        family=evidence.family,
        target_url=evidence.target_url,
        method=evidence.method,
        expected_strong_signals=(
            evidence.difference.strong_signals
        ),
    )
