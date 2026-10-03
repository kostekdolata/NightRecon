"""Integrity-verified local backup and recovery for Red Night workspaces."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tempfile
import zipfile


BACKUP_SCHEMA_VERSION = 1
MANIFEST_NAME = "nightrecon-workspace-manifest.json"
MAX_BACKUP_FILES = 5000
MAX_BACKUP_BYTES = 512 * 1024 * 1024
_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


@dataclass(frozen=True)
class WorkspaceBackupEntry:
    path: str
    size: int
    sha256: str

    def to_dict(self) -> dict[str, object]:
        return {"path": self.path, "size": self.size, "sha256": self.sha256}


@dataclass(frozen=True)
class WorkspaceBackupReport:
    schema_version: int
    file_count: int
    total_bytes: int
    manifest_sha256: str
    archive_sha256: str
    authorization_effect: str = "none"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "manifest_sha256": self.manifest_sha256,
            "archive_sha256": self.archive_sha256,
            "authorization_effect": self.authorization_effect,
        }


def _safe_relative(path: str) -> PurePosixPath:
    candidate = PurePosixPath(path)
    if (
        not path
        or candidate.is_absolute()
        or ".." in candidate.parts
        or "." in candidate.parts
        or "\\" in path
    ):
        raise ValueError(f"unsafe backup path: {path!r}")
    return candidate


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_entries(root: Path) -> tuple[WorkspaceBackupEntry, ...]:
    if not root.exists() or not root.is_dir():
        raise ValueError("workspace root must be an existing directory")

    entries: list[WorkspaceBackupEntry] = []
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"workspace backup refuses symlink: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            raise ValueError(f"workspace backup refuses non-regular file: {path}")
        relative = path.relative_to(root).as_posix()
        _safe_relative(relative)
        if relative == MANIFEST_NAME:
            raise ValueError("workspace contains reserved backup manifest path")
        size = path.stat().st_size
        total += size
        if len(entries) + 1 > MAX_BACKUP_FILES:
            raise ValueError("workspace backup file limit exceeded")
        if total > MAX_BACKUP_BYTES:
            raise ValueError("workspace backup size limit exceeded")
        entries.append(WorkspaceBackupEntry(
            path=relative,
            size=size,
            sha256=_sha256_file(path),
        ))
    return tuple(entries)


def _manifest_bytes(entries: tuple[WorkspaceBackupEntry, ...]) -> bytes:
    payload = {
        "schema_version": BACKUP_SCHEMA_VERSION,
        "authorization_effect": "none",
        "files": [entry.to_dict() for entry in entries],
    }
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _zip_write_bytes(
    archive: zipfile.ZipFile,
    name: str,
    data: bytes,
) -> None:
    info = zipfile.ZipInfo(name, date_time=_ZIP_TIMESTAMP)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o600 << 16
    archive.writestr(info, data)


def create_workspace_backup(
    workspace_root: str | Path,
    destination: str | Path,
) -> WorkspaceBackupReport:
    root = Path(workspace_root).resolve()
    output = Path(destination).resolve()
    if output == root or root in output.parents:
        raise ValueError("backup destination must be outside the workspace root")
    if output.exists():
        raise ValueError("backup destination already exists")

    entries = _source_entries(root)
    manifest = _manifest_bytes(entries)
    output.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(
        prefix=output.name + ".",
        suffix=".tmp",
        dir=str(output.parent),
    )
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        with zipfile.ZipFile(
            tmp,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            _zip_write_bytes(archive, MANIFEST_NAME, manifest)
            for entry in entries:
                _zip_write_bytes(
                    archive,
                    entry.path,
                    (root / Path(*PurePosixPath(entry.path).parts)).read_bytes(),
                )
        os.replace(tmp, output)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise

    return WorkspaceBackupReport(
        schema_version=BACKUP_SCHEMA_VERSION,
        file_count=len(entries),
        total_bytes=sum(entry.size for entry in entries),
        manifest_sha256=_sha256_bytes(manifest),
        archive_sha256=_sha256_file(output),
    )


def _load_verified_manifest(
    archive_path: Path,
) -> tuple[bytes, tuple[WorkspaceBackupEntry, ...]]:
    if not archive_path.exists() or not archive_path.is_file():
        raise ValueError("workspace backup archive not found")

    with zipfile.ZipFile(archive_path, "r") as archive:
        infos = archive.infolist()
        if len(infos) > MAX_BACKUP_FILES + 1:
            raise ValueError("workspace backup file limit exceeded")
        names = [info.filename for info in infos]
        if len(names) != len(set(names)):
            raise ValueError("workspace backup contains duplicate paths")
        if MANIFEST_NAME not in names:
            raise ValueError("workspace backup manifest is missing")

        for info in infos:
            safe = _safe_relative(info.filename)
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise ValueError(f"workspace backup contains symlink: {safe}")

        try:
            manifest_bytes = archive.read(MANIFEST_NAME)
            payload = json.loads(manifest_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError) as exc:
            raise ValueError("workspace backup manifest is invalid") from exc

        if not isinstance(payload, dict) or set(payload) != {
            "schema_version", "authorization_effect", "files"
        }:
            raise ValueError("workspace backup manifest schema is not supported")
        if payload["schema_version"] != BACKUP_SCHEMA_VERSION:
            raise ValueError("workspace backup schema version is not supported")
        if payload["authorization_effect"] != "none":
            raise ValueError("workspace backup cannot grant authorization")
        if not isinstance(payload["files"], list):
            raise ValueError("workspace backup manifest files are invalid")

        entries: list[WorkspaceBackupEntry] = []
        declared: set[str] = set()
        total = 0
        for item in payload["files"]:
            if not isinstance(item, dict) or set(item) != {"path", "size", "sha256"}:
                raise ValueError("workspace backup manifest entry is invalid")
            path = str(_safe_relative(item["path"]))
            if path == MANIFEST_NAME or path in declared:
                raise ValueError("workspace backup manifest contains duplicate/reserved path")
            size = item["size"]
            digest = item["sha256"]
            if not isinstance(size, int) or size < 0:
                raise ValueError("workspace backup manifest file size is invalid")
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(ch not in "0123456789abcdef" for ch in digest)
            ):
                raise ValueError("workspace backup manifest digest is invalid")
            total += size
            if len(entries) + 1 > MAX_BACKUP_FILES or total > MAX_BACKUP_BYTES:
                raise ValueError("workspace backup limits exceeded")
            declared.add(path)
            entries.append(WorkspaceBackupEntry(path, size, digest))

        payload_names = set(names) - {MANIFEST_NAME}
        if payload_names != declared:
            raise ValueError("workspace backup archive and manifest paths differ")

        for entry in entries:
            data = archive.read(entry.path)
            if len(data) != entry.size:
                raise ValueError(f"workspace backup size mismatch: {entry.path}")
            if _sha256_bytes(data) != entry.sha256:
                raise ValueError(f"workspace backup digest mismatch: {entry.path}")

    return manifest_bytes, tuple(entries)


def verify_workspace_backup(
    archive_path: str | Path,
) -> WorkspaceBackupReport:
    path = Path(archive_path)
    manifest, entries = _load_verified_manifest(path)
    return WorkspaceBackupReport(
        schema_version=BACKUP_SCHEMA_VERSION,
        file_count=len(entries),
        total_bytes=sum(entry.size for entry in entries),
        manifest_sha256=_sha256_bytes(manifest),
        archive_sha256=_sha256_file(path),
    )


def restore_workspace_backup(
    archive_path: str | Path,
    destination_root: str | Path,
) -> WorkspaceBackupReport:
    archive_path = Path(archive_path).resolve()
    destination = Path(destination_root).resolve()
    if destination.exists():
        raise ValueError("restore destination must not already exist")

    report = verify_workspace_backup(archive_path)
    _, entries = _load_verified_manifest(archive_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_root = Path(tempfile.mkdtemp(
        prefix=destination.name + ".restore-",
        dir=str(destination.parent),
    ))
    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            for entry in entries:
                target = temp_root.joinpath(*PurePosixPath(entry.path).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                data = archive.read(entry.path)
                target.write_bytes(data)
                if _sha256_file(target) != entry.sha256:
                    raise ValueError(f"restored file digest mismatch: {entry.path}")
        os.replace(temp_root, destination)
    except BaseException:
        shutil.rmtree(temp_root, ignore_errors=True)
        raise
    return report
