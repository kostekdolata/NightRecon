"""Configuration management for NightRecon."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NightReconConfig:
    """Runtime configuration for NightRecon."""

    connect_timeout: float = 2.0
    max_workers: int = 50
    results_dir: str = "results"
    logs_dir: str = "logs"

    def __post_init__(self) -> None:
        if self.connect_timeout <= 0:
            raise ValueError("connect_timeout must be greater than 0.")

        if self.max_workers < 1:
            raise ValueError("max_workers must be at least 1.")

        if not self.results_dir.strip():
            raise ValueError("results_dir cannot be empty.")

        if not self.logs_dir.strip():
            raise ValueError("logs_dir cannot be empty.")
