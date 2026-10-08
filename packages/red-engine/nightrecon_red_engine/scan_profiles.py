"""Deterministic Red Night scan timing/rate profiles."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanTimingProfile:
    name: str
    timeout_seconds: float
    max_workers: int
    retries: int
    max_probes_per_second: int

    def __post_init__(self) -> None:
        if self.name not in {"polite", "normal", "fast"}:
            raise ValueError("unsupported scan timing profile")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.max_workers < 1:
            raise ValueError("max_workers must be positive")
        if self.retries < 0:
            raise ValueError("retries must not be negative")
        if self.max_probes_per_second < 1:
            raise ValueError("max_probes_per_second must be positive")


SCAN_TIMING_PROFILES = {
    "polite": ScanTimingProfile(
        name="polite",
        timeout_seconds=2.0,
        max_workers=16,
        retries=1,
        max_probes_per_second=25,
    ),
    "normal": ScanTimingProfile(
        name="normal",
        timeout_seconds=1.0,
        max_workers=64,
        retries=1,
        max_probes_per_second=100,
    ),
    "fast": ScanTimingProfile(
        name="fast",
        timeout_seconds=0.5,
        max_workers=128,
        retries=0,
        max_probes_per_second=250,
    ),
}


def get_scan_timing_profile(name: str) -> ScanTimingProfile:
    try:
        return SCAN_TIMING_PROFILES[name.strip().lower()]
    except (AttributeError, KeyError) as exc:
        raise ValueError(
            "scan timing profile must be polite, normal, or fast"
        ) from exc
