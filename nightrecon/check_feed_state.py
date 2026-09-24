"""Persisted replay protection for verified NightRecon check feeds."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from nightrecon.check_feed import CheckPackFeed


_STATE_SCHEMA_VERSION = 1
_SAFE_FEED_ID = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*$"
)


@dataclass(frozen=True)
class AcceptedCheckFeedState:
    """Last accepted signed generation for one check feed."""

    feed_id: str
    generated_at: str
    manifest_sha256: str
    source_url: str


class CheckFeedStateStore:
    """Atomic local replay guard for verified signed feed manifests."""

    def __init__(
        self,
        root: str | Path,
    ) -> None:
        self.root = Path(root)

    def validate(
        self,
        feed: CheckPackFeed,
        *,
        source_url: str,
    ) -> AcceptedCheckFeedState:
        """Validate a verified feed generation without persisting it."""

        _validate_feed_id(
            feed.feed_id
        )
        incoming_time = _parse_generated_at(
            feed.generated_at
        )
        digest = _feed_digest(
            feed
        )
        existing = self.get(
            feed.feed_id
        )

        if existing is not None:
            existing_time = _parse_generated_at(
                existing.generated_at
            )

            if incoming_time < existing_time:
                raise ValueError(
                    "Signed check-feed generation is older and would "
                    "replay previously accepted state."
                )

            if (
                incoming_time == existing_time
                and digest != existing.manifest_sha256
            ):
                raise ValueError(
                    "Signed check feed has the same generation timestamp "
                    "but a different signed payload."
                )

            if (
                incoming_time == existing_time
                and digest == existing.manifest_sha256
            ):
                return existing

        return AcceptedCheckFeedState(
            feed_id=feed.feed_id,
            generated_at=feed.generated_at,
            manifest_sha256=digest,
            source_url=source_url,
        )

    def accept(
        self,
        feed: CheckPackFeed,
        *,
        source_url: str,
    ) -> AcceptedCheckFeedState:
        """Accept a verified feed only if it does not replay older state."""

        record = self.validate(
            feed,
            source_url=source_url,
        )
        existing = self.get(
            feed.feed_id
        )

        if existing == record:
            return existing

        self._write(
            record
        )
        return record

    def get(
        self,
        feed_id: str,
    ) -> AcceptedCheckFeedState | None:
        """Return the last accepted state for a feed, if present."""

        _validate_feed_id(
            feed_id
        )
        path = self._path(
            feed_id
        )

        if not path.exists():
            return None

        try:
            data = json.loads(
                path.read_text(
                    encoding="utf-8"
                )
            )
        except (
            OSError,
            json.JSONDecodeError,
        ) as exc:
            raise ValueError(
                "Installed check-feed state is invalid."
            ) from exc

        if (
            not isinstance(data, dict)
            or data.get("schema_version")
            != _STATE_SCHEMA_VERSION
        ):
            raise ValueError(
                "Installed check-feed state is invalid."
            )

        try:
            record = AcceptedCheckFeedState(
                feed_id=data["feed_id"],
                generated_at=data["generated_at"],
                manifest_sha256=data["manifest_sha256"],
                source_url=data["source_url"],
            )
        except (KeyError, TypeError) as exc:
            raise ValueError(
                "Installed check-feed state is invalid."
            ) from exc

        if record.feed_id != feed_id:
            raise ValueError(
                "Installed check-feed state is invalid."
            )

        _parse_generated_at(
            record.generated_at
        )

        return record

    def _path(
        self,
        feed_id: str,
    ) -> Path:
        return (
            self.root
            / "feeds"
            / f"{feed_id}.json"
        )

    def _write(
        self,
        record: AcceptedCheckFeedState,
    ) -> None:
        path = self._path(
            record.feed_id
        )
        data = {
            "schema_version": _STATE_SCHEMA_VERSION,
            **asdict(record),
        }
        encoded = json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        _atomic_write_bytes(
            path,
            encoded,
        )


def _feed_digest(
    feed: CheckPackFeed,
) -> str:
    payload = {
        "schema_version": feed.schema_version,
        "feed_id": feed.feed_id,
        "generated_at": feed.generated_at,
        "packs": [
            asdict(entry)
            for entry in feed.packs
        ],
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

    return hashlib.sha256(
        encoded
    ).hexdigest()


def _parse_generated_at(
    value: str,
) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(
            "Managed check feed requires generated_at."
        )

    text = value.strip()

    if text.endswith("Z"):
        text = (
            text[:-1]
            + "+00:00"
        )

    try:
        parsed = datetime.fromisoformat(
            text
        )
    except ValueError as exc:
        raise ValueError(
            "Managed check feed generated_at must be ISO 8601."
        ) from exc

    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
    ):
        raise ValueError(
            "Managed check feed generated_at must be timezone-aware."
        )

    return parsed


def _validate_feed_id(
    feed_id: str,
) -> None:
    if _SAFE_FEED_ID.fullmatch(
        feed_id
    ) is None:
        raise ValueError(
            f"Unsafe check-feed ID for storage: {feed_id}"
        )


def _atomic_write_bytes(
    path: Path,
    data: bytes,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )

    try:
        with os.fdopen(
            descriptor,
            "wb",
        ) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(
                handle.fileno()
            )

        os.replace(
            temporary_name,
            path,
        )
    except Exception:
        try:
            os.unlink(
                temporary_name
            )
        except OSError:
            pass
        raise
