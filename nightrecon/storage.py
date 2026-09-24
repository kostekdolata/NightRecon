"""Persistent storage for NightRecon results."""

from __future__ import annotations

import json
from pathlib import Path

from nightrecon.discovery_report import HostDiscoveryReport
from nightrecon.report import TcpScanReport
from nightrecon.session import ScanSession


class ResultStore:
    """Stores NightRecon result data as JSON files."""

    def __init__(self, root: str | Path = "results") -> None:
        self.root = Path(root)

    def save_session(self, session: ScanSession) -> Path:
        """Save a scan session."""

        return self._save_json(
            session_id=session.session_id,
            data=session.to_dict(),
        )

    def save_report(self, report: TcpScanReport) -> Path:
        """Save a completed TCP scan report."""

        return self._save_json(
            session_id=report.session_id,
            data=report.to_dict(),
        )

    def save_discovery_report(
        self,
        report: HostDiscoveryReport,
    ) -> Path:
        """Save a completed host-discovery report."""

        return self._save_json(
            session_id=report.session_id,
            data=report.to_dict(),
        )

    def _save_json(
        self,
        session_id: str,
        data: dict,
    ) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)

        output_path = self.root / f"{session_id}.json"

        with output_path.open("w", encoding="utf-8") as file:
            json.dump(
                data,
                file,
                indent=2,
                sort_keys=True,
            )
            file.write("\n")

        return output_path
