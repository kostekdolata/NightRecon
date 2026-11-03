"""Managed external-tool discovery, without fetching or executing tools.

An administrator-approved manifest pins a relative component path and SHA-256.
The program lives inside the explicitly supplied managed components directory.
No PATH lookup, auto-download, shell, or elevation is performed.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re

_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")


@dataclass(frozen=True)
class ManagedComponent:
    name: str
    executable: Path
    sha256: str


def resolve_managed_component(
    *, components_root: str | Path, manifest_path: str | Path,
    component_name: str = "nmap",
) -> ManagedComponent:
    root = Path(components_root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Managed components root is not a directory")
    manifest_file = Path(manifest_path).resolve(strict=True)
    # Manifest cannot be swapped for a file outside the managed directory.
    if not manifest_file.is_relative_to(root):
        raise PermissionError("Component manifest is outside managed root")
    if manifest_file.stat().st_size > 32768:
        raise ValueError("Component manifest exceeds size limit")
    document = json.loads(manifest_file.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or set(document) != {"schema", "components"}:
        raise ValueError("Invalid managed component manifest")
    if document["schema"] != 1 or not isinstance(document["components"], dict):
        raise ValueError("Unsupported managed component manifest")
    entry = document["components"].get(component_name)
    if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
        raise PermissionError("Managed component has no approved manifest entry")
    relative = entry["path"]
    digest = entry["sha256"]
    if not isinstance(relative, str) or not isinstance(digest, str):
        raise ValueError("Invalid managed component fields")
    normalized = PurePosixPath(relative)
    if (normalized.is_absolute() or not normalized.parts or
            any(part in (".", "..") for part in relative.split("/")) or
            "\\" in relative or ":" in relative):
        raise ValueError("Managed executable path must be relative and normalised")
    candidate = (root / Path(*normalized.parts)).resolve(strict=True)
    if not candidate.is_relative_to(root):
        raise PermissionError("Managed executable resolves outside root")
    if candidate.name.lower() not in ("nmap", "nmap.exe") or component_name != "nmap":
        raise PermissionError("Unsupported managed component")
    if not candidate.is_file() or _SHA256.fullmatch(digest) is None:
        raise ValueError("Managed executable or checksum is invalid")
    with candidate.open("rb") as stream:
        actual = hashlib.file_digest(stream, "sha256").hexdigest()
    if actual != digest.lower():
        raise PermissionError("Managed executable digest mismatch")
    return ManagedComponent(name=component_name, executable=candidate, sha256=digest.lower())
