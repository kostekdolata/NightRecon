"""Structured logging for NightRecon."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class NightReconLogger:
    """Writes structured JSON Lines audit logs."""

    def __init__(self, root: str | Path = "logs") -> None:
        self.root = Path(root)

    def write(
        self,
        event: str,
        **data: Any,
    ) -> Path:
        self.root.mkdir(parents=True, exist_ok=True)

        log_path = self.root / "nightrecon.jsonl"

        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **data,
        }

        with log_path.open("a", encoding="utf-8") as file:
            file.write(json.dumps(record, sort_keys=True))
            file.write("\n")

        return log_path
