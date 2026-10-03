"""Structured, secret-safe logging for NightRecon."""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_REDACTED = "<redacted>"
_SENSITIVE_EXACT_KEYS = frozenset({
    "password",
    "passwd",
    "passphrase",
    "secret",
    "secret_key",
    "client_secret",
    "api_key",
    "apikey",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "proxy_authorization",
    "cookie",
    "set_cookie",
    "private_key",
    "credential_material",
})
_SENSITIVE_SUFFIXES = (
    "_password",
    "_passwd",
    "_passphrase",
    "_secret",
    "_token",
    "_api_key",
    "_apikey",
    "_cookie",
    "_private_key",
)
_AUTH_VALUE = re.compile(r"^(?:bearer|basic)\s+\S+", re.IGNORECASE)
_SECRET_OBJECT_NAMES = frozenset({"EphemeralSecret", "ResolvedCredential"})


def _normalized_key(value: object) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).lower()).strip("_")


def _sensitive_key(value: object) -> bool:
    normalized = _normalized_key(value)
    return (
        normalized in _SENSITIVE_EXACT_KEYS
        or any(normalized.endswith(suffix) for suffix in _SENSITIVE_SUFFIXES)
    )


def _sanitize(value: Any, *, key: object | None = None) -> Any:
    if key is not None and _sensitive_key(key):
        return _REDACTED
    if value.__class__.__name__ in _SECRET_OBJECT_NAMES:
        return _REDACTED
    if isinstance(value, dict):
        return {
            str(item_key): _sanitize(item_value, key=item_key)
            for item_key, item_value in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    if isinstance(value, str) and _AUTH_VALUE.match(value.strip()):
        return _REDACTED
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(
        "NightRecon log values must be JSON primitives, mappings, or sequences"
    )


def _append_private_json_line(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    fd = os.open(path, flags, 0o600)
    try:
        if os.name != "nt":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8", newline="\n") as handle:
            handle.write(line)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


class NightReconLogger:
    """Writes secret-safe structured JSON Lines audit logs."""

    def __init__(self, root: str | Path = "logs") -> None:
        self.root = Path(root)

    def write(
        self,
        event: str,
        **data: Any,
    ) -> Path:
        if not isinstance(event, str) or not event.strip():
            raise ValueError("event must be a nonblank string")

        log_path = self.root / "nightrecon.jsonl"
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **_sanitize(data),
        }
        _append_private_json_line(
            log_path,
            json.dumps(record, sort_keys=True, separators=(",", ":")),
        )
        return log_path
