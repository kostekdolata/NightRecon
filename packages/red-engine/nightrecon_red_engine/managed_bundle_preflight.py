"""Offline preflight for an installer-staged managed Nmap distribution.

This checks manifest integrity and the mandatory installed-tool layout.
It neither downloads nor executes Nmap; it is safe for build and installer CI.
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from .managed_components import resolve_managed_component

@dataclass(frozen=True)
class StagingPreflight:
    executable: Path
    sha256: str
    bundled: bool
    warnings: tuple[str, ...]

def preflight_nmap_bundle(*, components_root: str | Path,
                          manifest_path: str | Path,
                          require_bundle: bool = False) -> StagingPreflight:
    root = Path(components_root)
    manifest = Path(manifest_path)
    if not root.exists() or not manifest.exists():
        if require_bundle:
            raise FileNotFoundError("Required managed Nmap bundle is missing")
        return StagingPreflight(Path(), "", False,
            ("Nmap not bundled; managed discovery is unavailable",))
    component = resolve_managed_component(
        components_root=root, manifest_path=manifest, component_name="nmap")
    # A test fixture or wrong-architecture binary may have a matching checksum.
    # Packaging must also validate platform, binary format, architecture and
    # bundled licensing notices before setting require_bundle=True in releases.
    return StagingPreflight(component.executable, component.sha256, True,
        ("Executable provenance, format, architecture and licensing require independent release verification",))
