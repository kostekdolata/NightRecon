"""Integrity-verified local backup and recovery for Red Night workspaces."""

from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import tempfile
import zipfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


BACKUP_SCHEMA_VERSION = 1
MANIFEST_NAME = "nightrecon-workspace-manifest.json"
MAX_BACKUP_FILES = 5000
MAX_BACKUP_BYTES = 512 * 1024 * 1024
_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
ENCRYPTED_BACKUP_FORMAT = "nightrecon-red-workspace-encrypted-v1"
_ENCRYPTED_MAGIC = b"NIGHTRECON-RED-WORKSPACE-ENC-V1\n"
_ENCRYPTED_TAG_BYTES = 16
_ENCRYPTED_HEADER_MAX_BYTES = 4096
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_ENCRYPTION_CHUNK_BYTES = 1024 * 1024


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

@dataclass(frozen=True)
class EncryptedWorkspaceBackupReport:
    schema_version: int
    file_count: int
    total_bytes: int
    manifest_sha256: str
    plaintext_archive_sha256: str
    encrypted_archive_sha256: str
    encryption_format: str = ENCRYPTED_BACKUP_FORMAT
    authorization_effect: str = "none"

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "manifest_sha256": self.manifest_sha256,
            "plaintext_archive_sha256": self.plaintext_archive_sha256,
            "encrypted_archive_sha256": self.encrypted_archive_sha256,
            "encryption_format": self.encryption_format,
            "authorization_effect": self.authorization_effect,
        }


def _validate_passphrase(passphrase: bytes) -> bytes:
    if not isinstance(passphrase, bytes):
        raise TypeError("workspace backup passphrase must be bytes")
    if len(passphrase) < 12:
        raise ValueError("workspace backup passphrase must be at least 12 bytes")
    if len(passphrase) > 1024:
        raise ValueError("workspace backup passphrase exceeds 1024 bytes")
    return passphrase


def _derive_backup_key(passphrase: bytes, salt: bytes) -> bytes:
    return Scrypt(
        salt=salt,
        length=32,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
    ).derive(_validate_passphrase(passphrase))


def _encrypted_header(salt: bytes, nonce: bytes) -> bytes:
    payload = {
        "format": ENCRYPTED_BACKUP_FORMAT,
        "kdf": "scrypt",
        "n": _SCRYPT_N,
        "r": _SCRYPT_R,
        "p": _SCRYPT_P,
        "cipher": "aes-256-gcm",
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "authorization_effect": "none",
    }
    return (
        json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _parse_encrypted_header(header_bytes: bytes) -> tuple[bytes, bytes]:
    if len(header_bytes) > _ENCRYPTED_HEADER_MAX_BYTES:
        raise ValueError("encrypted workspace backup header is too large")
    try:
        payload = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("encrypted workspace backup header is invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "format", "kdf", "n", "r", "p", "cipher",
        "salt_b64", "nonce_b64", "authorization_effect",
    }:
        raise ValueError("encrypted workspace backup header schema is not supported")
    if (
        payload["format"] != ENCRYPTED_BACKUP_FORMAT
        or payload["kdf"] != "scrypt"
        or payload["n"] != _SCRYPT_N
        or payload["r"] != _SCRYPT_R
        or payload["p"] != _SCRYPT_P
        or payload["cipher"] != "aes-256-gcm"
    ):
        raise ValueError("encrypted workspace backup cryptographic parameters are unsupported")
    if payload["authorization_effect"] != "none":
        raise ValueError("encrypted workspace backup cannot grant authorization")
    try:
        salt = base64.b64decode(payload["salt_b64"], validate=True)
        nonce = base64.b64decode(payload["nonce_b64"], validate=True)
    except (TypeError, ValueError) as exc:
        raise ValueError("encrypted workspace backup header encoding is invalid") from exc
    if len(salt) != 16 or len(nonce) != 12:
        raise ValueError("encrypted workspace backup salt or nonce size is invalid")
    return salt, nonce


def _encrypt_backup_file(
    plaintext: Path,
    destination: Path,
    *,
    passphrase: bytes,
) -> None:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    header = _encrypted_header(salt, nonce)
    key = _derive_backup_key(passphrase, salt)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(_ENCRYPTED_MAGIC + header)

    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=destination.name + ".",
        suffix=".tmp",
        dir=str(destination.parent),
    )
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as output, plaintext.open("rb") as source:
            output.write(_ENCRYPTED_MAGIC)
            output.write(header)
            for chunk in iter(lambda: source.read(_ENCRYPTION_CHUNK_BYTES), b""):
                output.write(encryptor.update(chunk))
            output.write(encryptor.finalize())
            output.write(encryptor.tag)
            output.flush()
            os.fsync(output.fileno())
        os.replace(tmp, destination)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise


def _decrypt_backup_file(
    encrypted: Path,
    destination: Path,
    *,
    passphrase: bytes,
) -> None:
    if not encrypted.exists() or not encrypted.is_file():
        raise ValueError("encrypted workspace backup archive not found")
    with encrypted.open("rb") as source:
        if source.readline(len(_ENCRYPTED_MAGIC) + 1) != _ENCRYPTED_MAGIC:
            raise ValueError("encrypted workspace backup magic is invalid")
        header = source.readline(_ENCRYPTED_HEADER_MAX_BYTES + 1)
        if not header.endswith(b"\n") or len(header) > _ENCRYPTED_HEADER_MAX_BYTES:
            raise ValueError("encrypted workspace backup header is invalid")
        data_start = source.tell()
        salt, nonce = _parse_encrypted_header(header)
        total_size = encrypted.stat().st_size
        ciphertext_length = total_size - data_start - _ENCRYPTED_TAG_BYTES
        if ciphertext_length < 1:
            raise ValueError("encrypted workspace backup payload is missing")
        source.seek(total_size - _ENCRYPTED_TAG_BYTES)
        tag = source.read(_ENCRYPTED_TAG_BYTES)
        source.seek(data_start)

        key = _derive_backup_key(passphrase, salt)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(_ENCRYPTED_MAGIC + header)

        destination.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(
            prefix=destination.name + ".",
            suffix=".tmp",
            dir=str(destination.parent),
        )
        tmp = Path(tmp_name)
        remaining = ciphertext_length
        try:
            with os.fdopen(fd, "wb") as output:
                while remaining:
                    chunk = source.read(min(_ENCRYPTION_CHUNK_BYTES, remaining))
                    if not chunk:
                        raise ValueError("encrypted workspace backup payload is truncated")
                    remaining -= len(chunk)
                    output.write(decryptor.update(chunk))
                try:
                    output.write(decryptor.finalize())
                except InvalidTag as exc:
                    raise ValueError(
                        "encrypted workspace backup authentication failed"
                    ) from exc
                output.flush()
                os.fsync(output.fileno())
            os.replace(tmp, destination)
        except BaseException:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise


def create_encrypted_workspace_backup(
    workspace_root: str | Path,
    destination: str | Path,
    *,
    passphrase: bytes,
) -> EncryptedWorkspaceBackupReport:
    output = Path(destination).resolve()
    if output.exists():
        raise ValueError("encrypted backup destination already exists")
    with tempfile.TemporaryDirectory(prefix="nightrecon-backup-encrypt-") as temp:
        plaintext = Path(temp) / "workspace.nrwb"
        inner = create_workspace_backup(workspace_root, plaintext)
        _encrypt_backup_file(plaintext, output, passphrase=passphrase)
    return EncryptedWorkspaceBackupReport(
        schema_version=inner.schema_version,
        file_count=inner.file_count,
        total_bytes=inner.total_bytes,
        manifest_sha256=inner.manifest_sha256,
        plaintext_archive_sha256=inner.archive_sha256,
        encrypted_archive_sha256=_sha256_file(output),
    )


def _decrypt_and_verify_workspace_backup(
    archive_path: str | Path,
    *,
    passphrase: bytes,
    temp_root: Path,
) -> tuple[Path, EncryptedWorkspaceBackupReport]:
    encrypted = Path(archive_path).resolve()
    plaintext = temp_root / "decrypted.nrwb"
    _decrypt_backup_file(encrypted, plaintext, passphrase=passphrase)
    inner = verify_workspace_backup(plaintext)
    report = EncryptedWorkspaceBackupReport(
        schema_version=inner.schema_version,
        file_count=inner.file_count,
        total_bytes=inner.total_bytes,
        manifest_sha256=inner.manifest_sha256,
        plaintext_archive_sha256=inner.archive_sha256,
        encrypted_archive_sha256=_sha256_file(encrypted),
    )
    return plaintext, report


def verify_encrypted_workspace_backup(
    archive_path: str | Path,
    *,
    passphrase: bytes,
) -> EncryptedWorkspaceBackupReport:
    with tempfile.TemporaryDirectory(prefix="nightrecon-backup-verify-") as temp:
        _, report = _decrypt_and_verify_workspace_backup(
            archive_path,
            passphrase=passphrase,
            temp_root=Path(temp),
        )
        return report


def restore_encrypted_workspace_backup(
    archive_path: str | Path,
    destination_root: str | Path,
    *,
    passphrase: bytes,
) -> EncryptedWorkspaceBackupReport:
    destination = Path(destination_root).resolve()
    if destination.exists():
        raise ValueError("restore destination must not already exist")
    with tempfile.TemporaryDirectory(prefix="nightrecon-backup-restore-") as temp:
        plaintext, report = _decrypt_and_verify_workspace_backup(
            archive_path,
            passphrase=passphrase,
            temp_root=Path(temp),
        )
        restore_workspace_backup(plaintext, destination)
        return report

