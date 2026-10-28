"""Stage a pre-approved Nmap binary for Red Night managed components.

Offline only. The caller supplies the trusted SHA-256 obtained from an
independent release process. This is not a downloader or installer.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

from .managed_components import resolve_managed_component

_DIGEST = re.compile(r"^[a-fA-F0-9]{64}$")


def stage_trusted_nmap(
    *, source: str | Path, components_root: str | Path, trusted_sha256: str,
) -> Path:
    if not isinstance(trusted_sha256, str) or not _DIGEST.fullmatch(trusted_sha256):
        raise ValueError("An independently approved SHA-256 is required")
    origin = Path(source).resolve(strict=True)
    if not origin.is_file() or origin.name.lower() not in ("nmap", "nmap.exe"):
        raise ValueError("Source must be an existing Nmap executable")
    root = Path(components_root)
    root.mkdir(parents=True, exist_ok=True)
    root = root.resolve(strict=True)
    destination = root / origin.name
    manifest = root / "components.json"
    if destination.exists() or destination.is_symlink() or manifest.exists() or manifest.is_symlink():
        raise FileExistsError("Managed installation already staged; refusing overwrite")
    with origin.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != trusted_sha256.lower():
            raise PermissionError("Nmap source checksum does not match release approval")
    fd, temporary = tempfile.mkstemp(prefix=".nmap-staging-", dir=root)
    try:
        with os.fdopen(fd, "wb") as out, origin.open("rb") as inp:
            shutil.copyfileobj(inp, out, length=65536)
            out.flush()
            os.fsync(out.fileno())
        with Path(temporary).open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != trusted_sha256.lower():
                raise PermissionError("Nmap changed during staging")
        os.chmod(temporary, 0o755)
        os.replace(temporary, destination)
        temporary = None
        payload = {"schema": 1, "components": {"nmap": {
            "path": destination.name, "sha256": trusted_sha256.lower(),
        }}}
        try:
            with manifest.open("x", encoding="utf-8") as out:
                json.dump(payload, out, sort_keys=True)
                out.write("\n")
                out.flush()
                os.fsync(out.fileno())
            resolve_managed_component(
                components_root=root, manifest_path=manifest, component_name="nmap")
        except BaseException:
            manifest.unlink(missing_ok=True)
            destination.unlink(missing_ok=True)
            raise
        return destination
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)
