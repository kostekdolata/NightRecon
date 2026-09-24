"""Verified local storage for signed NightRecon check packs."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from nightrecon.check_pack_signing import (
    load_signed_check_pack,
)
from nightrecon.check_packs import CheckPack


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SAFE_VERSION = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._+-]*$"
)


@dataclass(frozen=True)
class InstalledCheckPackRecord:
    """One immutable signed check-pack version stored locally."""

    pack_id: str
    version: str
    signer_key_id: str
    sha256: str
    path: str


class CheckPackStore:
    """Atomic local store for verified signed check packs."""

    def __init__(
        self,
        root: str | Path,
    ) -> None:
        self.root = Path(root)

    def install_signed_pack(
        self,
        text: str,
        *,
        trusted_keys: dict[str, bytes],
    ) -> InstalledCheckPackRecord:
        """Verify, store, and activate one immutable signed pack version."""

        pack = load_signed_check_pack(
            text,
            trusted_keys=trusted_keys,
        )
        signer_key_id = _extract_signer_key_id(
            text
        )

        _validate_storage_component(
            pack.pack_id,
            label="check-pack ID",
        )
        _validate_storage_component(
            pack.version,
            label="check-pack version",
            version=True,
        )

        data = text.encode("utf-8")
        digest = hashlib.sha256(
            data
        ).hexdigest()
        pack_dir = self._pack_dir(
            pack.pack_id
        )
        pack_dir.mkdir(
            parents=True,
            exist_ok=True,
        )
        destination = self._version_path(
            pack.pack_id,
            pack.version,
        )

        if destination.exists():
            existing_digest = hashlib.sha256(
                destination.read_bytes()
            ).hexdigest()

            if existing_digest != digest:
                raise ValueError(
                    "Installed check-pack versions are immutable."
                )
        else:
            _atomic_write_bytes(
                destination,
                data,
            )

        state = self._read_state(
            pack.pack_id
        )
        active_version = state.get(
            "active_version"
        )
        history = _state_history(
            state
        )

        if (
            isinstance(active_version, str)
            and active_version
            and active_version != pack.version
        ):
            history.append(
                active_version
            )

        if active_version != pack.version:
            self._write_state(
                pack.pack_id,
                active_version=pack.version,
                history=history,
            )

        return InstalledCheckPackRecord(
            pack_id=pack.pack_id,
            version=pack.version,
            signer_key_id=signer_key_id,
            sha256=digest,
            path=str(destination),
        )

    def list_pack_ids(self) -> tuple[str, ...]:
        """Return installed check-pack IDs in deterministic order."""

        packs_root = self.root / "packs"

        if not packs_root.exists():
            return ()

        return tuple(
            sorted(
                path.name
                for path in packs_root.iterdir()
                if (
                    path.is_dir()
                    and _SAFE_ID.fullmatch(path.name)
                    is not None
                )
            )
        )

    def active_version(
        self,
        pack_id: str,
    ) -> str | None:
        """Return the active stored version for a pack, if any."""

        _validate_storage_component(
            pack_id,
            label="check-pack ID",
        )
        state = self._read_state(
            pack_id
        )
        value = state.get(
            "active_version"
        )

        if isinstance(value, str) and value:
            return value

        return None

    def list_versions(
        self,
        pack_id: str,
    ) -> tuple[InstalledCheckPackRecord, ...]:
        """List locally stored immutable versions for one pack."""

        _validate_storage_component(
            pack_id,
            label="check-pack ID",
        )
        pack_dir = self._pack_dir(
            pack_id
        )

        if not pack_dir.exists():
            return ()

        records: list[InstalledCheckPackRecord] = []

        for path in sorted(
            pack_dir.glob("*.signed.json"),
            key=lambda item: item.name,
        ):
            version = path.name[
                : -len(".signed.json")
            ]

            try:
                text = path.read_text(
                    encoding="utf-8"
                )
                signer_key_id = (
                    _extract_signer_key_id(
                        text
                    )
                )
            except (OSError, ValueError):
                signer_key_id = ""

            try:
                digest = hashlib.sha256(
                    path.read_bytes()
                ).hexdigest()
            except OSError:
                digest = ""

            records.append(
                InstalledCheckPackRecord(
                    pack_id=pack_id,
                    version=version,
                    signer_key_id=signer_key_id,
                    sha256=digest,
                    path=str(path),
                )
            )

        return tuple(records)

    def load_active(
        self,
        pack_id: str,
        *,
        trusted_keys: dict[str, bytes],
    ) -> CheckPack:
        """Load and re-verify the currently active signed pack."""

        version = self.active_version(
            pack_id
        )

        if version is None:
            raise ValueError(
                f"No active check-pack version: {pack_id}"
            )

        path = self._version_path(
            pack_id,
            version,
        )

        try:
            text = path.read_text(
                encoding="utf-8"
            )
        except OSError as exc:
            raise ValueError(
                "Unable to read active check-pack version."
            ) from exc

        pack = load_signed_check_pack(
            text,
            trusted_keys=trusted_keys,
        )

        if (
            pack.pack_id != pack_id
            or pack.version != version
        ):
            raise ValueError(
                "Active check-pack metadata does not match storage state."
            )

        return pack

    def rollback(
        self,
        pack_id: str,
    ) -> str:
        """Restore the most recently replaced active version."""

        _validate_storage_component(
            pack_id,
            label="check-pack ID",
        )
        state = self._read_state(
            pack_id
        )
        history = _state_history(
            state
        )

        if not history:
            raise ValueError(
                "No previous active version is available."
            )

        previous = history.pop()

        if not self._version_path(
            pack_id,
            previous,
        ).exists():
            raise ValueError(
                "Previous active check-pack version is missing."
            )

        self._write_state(
            pack_id,
            active_version=previous,
            history=history,
        )

        return previous

    def _pack_dir(
        self,
        pack_id: str,
    ) -> Path:
        return self.root / "packs" / pack_id

    def _version_path(
        self,
        pack_id: str,
        version: str,
    ) -> Path:
        _validate_storage_component(
            version,
            label="check-pack version",
            version=True,
        )
        return (
            self._pack_dir(pack_id)
            / f"{version}.signed.json"
        )

    def _state_path(
        self,
        pack_id: str,
    ) -> Path:
        return (
            self._pack_dir(pack_id)
            / "state.json"
        )

    def _read_state(
        self,
        pack_id: str,
    ) -> dict[str, object]:
        path = self._state_path(
            pack_id
        )

        if not path.exists():
            return {}

        try:
            payload = json.loads(
                path.read_text(
                    encoding="utf-8"
                )
            )
        except (
            OSError,
            json.JSONDecodeError,
        ) as exc:
            raise ValueError(
                "Installed check-pack state is invalid."
            ) from exc

        if not isinstance(payload, dict):
            raise ValueError(
                "Installed check-pack state is invalid."
            )

        return payload

    def _write_state(
        self,
        pack_id: str,
        *,
        active_version: str,
        history: list[str],
    ) -> None:
        path = self._state_path(
            pack_id
        )
        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        data = json.dumps(
            {
                "active_version": active_version,
                "history": history,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        _atomic_write_bytes(
            path,
            data,
        )


def _extract_signer_key_id(
    text: str,
) -> str:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "Invalid signed check-pack JSON."
        ) from exc

    if not isinstance(document, dict):
        raise ValueError(
            "Signed check pack must be a JSON object."
        )

    key_id = document.get(
        "key_id"
    )

    if not isinstance(key_id, str) or not key_id.strip():
        raise ValueError(
            "Signed check pack requires key_id."
        )

    return key_id.strip()


def _validate_storage_component(
    value: str,
    *,
    label: str,
    version: bool = False,
) -> None:
    pattern = (
        _SAFE_VERSION
        if version
        else _SAFE_ID
    )

    if pattern.fullmatch(value) is None:
        if label == "check-pack ID":
            raise ValueError(
                f"Unsafe check-pack ID for storage: {value}"
            )

        raise ValueError(
            f"Unsafe {label} for storage: {value}"
        )


def _state_history(
    state: dict[str, object],
) -> list[str]:
    value = state.get(
        "history",
        [],
    )

    if not isinstance(value, list):
        raise ValueError(
            "Installed check-pack state is invalid."
        )

    history: list[str] = []

    for item in value:
        if not isinstance(item, str):
            raise ValueError(
                "Installed check-pack state is invalid."
            )
        history.append(item)

    return history


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
