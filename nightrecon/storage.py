"""Persistent storage for NightRecon results."""

from __future__ import annotations

import json
from pathlib import Path

from nightrecon.session import ScanSession


class ResultStore:
    """Stores NightRecon session data as JSON files."""

    def __init__(self, root: str | Path = "results") -> None:
        self.root = Path(root)

    def save_session(self, session: ScanSession) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)

        output_path = self.root / f"{session.session_id}.json"

        with output_path.open("w", encoding="utf-8") as file:
            json.dump(
                session.to_dict(),
                file,
                indent=2,
                sort_keys=True,
            )
            file.write("\n")

        return output_path
