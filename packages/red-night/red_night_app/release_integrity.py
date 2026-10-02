"""Deterministic Red Night release artifact integrity manifests."""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from typing import Mapping, Sequence

RELEASE_MANIFEST_FORMAT = "nightrecon-red-release-manifest-v1"
_ALLOWED_ROLES = frozenset({
    "shared-core-wheel",
    "red-engine-wheel",
    "red-app-wheel",
    "live-image",
    "sbom",
})
_REQUIRED_PACKAGE_ROLES = frozenset({
    "shared-core-wheel",
    "red-engine-wheel",
    "red-app-wheel",
})


def _safe_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("artifact path must be a nonblank trimmed string")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("artifact path must remain relative to the release root")
    return path.as_posix()


def _sha256_hex(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError("artifact sha256 must be lowercase hexadecimal")
    return value


@dataclass(frozen=True)
class ReleaseArtifact:
    path: str
    role: str
    size_bytes: int
    sha256: str

    def __post_init__(self) -> None:
        _safe_relative_path(self.path)
        if self.role not in _ALLOWED_ROLES:
            raise ValueError(f"unsupported release artifact role: {self.role}")
        if not isinstance(self.size_bytes, int) or self.size_bytes < 0:
            raise ValueError("artifact size_bytes must be a non-negative integer")
        _sha256_hex(self.sha256)

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "role": self.role,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "ReleaseArtifact":
        if not isinstance(payload, Mapping) or set(payload) != {
            "path", "role", "size_bytes", "sha256"
        }:
            raise ValueError("release artifact schema is not supported")
        return cls(
            path=payload["path"],
            role=payload["role"],
            size_bytes=payload["size_bytes"],
            sha256=payload["sha256"],
        )


@dataclass(frozen=True)
class RedReleaseManifest:
    release_version: str
    deployment_profile: str
    artifacts: tuple[ReleaseArtifact, ...]
    format: str = RELEASE_MANIFEST_FORMAT

    def __post_init__(self) -> None:
        if self.format != RELEASE_MANIFEST_FORMAT:
            raise ValueError("unsupported Red release manifest format")
        if not isinstance(self.release_version, str) or not self.release_version.strip():
            raise ValueError("release_version must be nonblank")
        if self.deployment_profile not in {"standalone", "composed", "live-usb"}:
            raise ValueError("unsupported Red deployment profile")
        paths = [item.path for item in self.artifacts]
        if len(paths) != len(set(paths)):
            raise ValueError("release artifact paths must be unique")
        roles = [item.role for item in self.artifacts]
        for role in _REQUIRED_PACKAGE_ROLES:
            if roles.count(role) != 1:
                raise ValueError(
                    f"release manifest requires exactly one {role} artifact"
                )
        if self.deployment_profile == "live-usb" and roles.count("live-image") != 1:
            raise ValueError("live-usb release manifest requires one live-image artifact")

    def to_dict(self) -> dict[str, object]:
        return {
            "format": self.format,
            "release_version": self.release_version,
            "deployment_profile": self.deployment_profile,
            "artifacts": [item.to_dict() for item in self.artifacts],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "RedReleaseManifest":
        if not isinstance(payload, Mapping) or set(payload) != {
            "format", "release_version", "deployment_profile", "artifacts"
        }:
            raise ValueError("Red release manifest schema is not supported")
        artifacts = payload["artifacts"]
        if not isinstance(artifacts, list):
            raise ValueError("release artifacts must be a list")
        return cls(
            format=payload["format"],
            release_version=payload["release_version"],
            deployment_profile=payload["deployment_profile"],
            artifacts=tuple(ReleaseArtifact.from_dict(item) for item in artifacts),
        )


def hash_release_artifact(path: Path, *, release_root: Path, role: str) -> ReleaseArtifact:
    root = release_root.resolve()
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("release artifact must be inside the release root") from exc
    digest = sha256()
    with resolved.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return ReleaseArtifact(
        path=relative.as_posix(),
        role=role,
        size_bytes=resolved.stat().st_size,
        sha256=digest.hexdigest(),
    )


def build_red_release_manifest(
    *,
    release_root: Path,
    release_version: str,
    deployment_profile: str,
    artifacts: Sequence[tuple[Path, str]],
) -> RedReleaseManifest:
    return RedReleaseManifest(
        release_version=release_version,
        deployment_profile=deployment_profile,
        artifacts=tuple(
            hash_release_artifact(path, release_root=release_root, role=role)
            for path, role in artifacts
        ),
    )


def verify_red_release_manifest(
    manifest: RedReleaseManifest,
    *,
    release_root: Path,
) -> None:
    root = release_root.resolve()
    for artifact in manifest.artifacts:
        path = (root / _safe_relative_path(artifact.path)).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValueError("release artifact escapes the release root") from exc
        if not path.is_file():
            raise ValueError(f"release artifact is missing: {artifact.path}")
        if path.stat().st_size != artifact.size_bytes:
            raise ValueError(f"release artifact size mismatch: {artifact.path}")
        actual = hash_release_artifact(path, release_root=root, role=artifact.role)
        if actual.sha256 != artifact.sha256:
            raise ValueError(f"release artifact digest mismatch: {artifact.path}")
