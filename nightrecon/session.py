"""Scan session models for NightRecon."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from uuid import uuid4

from nightrecon.targets import Target


@dataclass(frozen=True)
class ScanSession:
    session_id: str
    created_at: str
    target: str
    target_type: str
    scope: tuple[str, ...]
    status: str

    @classmethod
    def create(
        cls,
        target: Target,
        scope_rules: tuple[str, ...],
    ) -> "ScanSession":
        return cls(
            session_id=str(uuid4()),
            created_at=datetime.now(timezone.utc).isoformat(),
            target=target.value,
            target_type=target.target_type.value,
            scope=scope_rules,
            status="created",
        )

    def to_dict(self) -> dict:
        return asdict(self)
