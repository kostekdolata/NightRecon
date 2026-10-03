"""Create deterministic integrity metadata for a Red Night Windows installer."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--installer", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--wheels", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    for path, label in (
        (args.installer, "installer"),
        (args.sbom, "SBOM"),
    ):
        if not path.is_file():
            raise SystemExit(f"{label} not found: {path}")
    if not args.bundle.is_dir():
        raise SystemExit(f"bundle not found: {args.bundle}")
    if not args.wheels.is_dir():
        raise SystemExit(f"wheel directory not found: {args.wheels}")

    wheel_entries = [
        {"name": path.name, "sha256": sha256(path), "size": path.stat().st_size}
        for path in sorted(args.wheels.glob("*.whl"))
    ]
    if len(wheel_entries) != 3:
        raise SystemExit(f"expected exactly three Red wheels, found {len(wheel_entries)}")

    executable = args.bundle / "RedNight.exe"
    build_info = args.bundle / "build-info.json"
    if not executable.is_file() or not build_info.is_file():
        raise SystemExit("prepared bundle is missing RedNight.exe or build-info.json")

    payload = {
        "schema_version": 1,
        "product": "Red Night",
        "installer_version": args.version,
        "source_commit": args.source_commit,
        "installer": {
            "name": args.installer.name,
            "sha256": sha256(args.installer),
            "size": args.installer.stat().st_size,
        },
        "bundle": {
            "executable_sha256": sha256(executable),
            "build_info_sha256": sha256(build_info),
        },
        "wheels": wheel_entries,
        "sbom": {
            "name": args.sbom.name,
            "sha256": sha256(args.sbom),
            "size": args.sbom.stat().st_size,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    checksum = args.output.with_name("SHA256SUMS.txt")
    checksum.write_text(
        f"{payload['installer']['sha256']}  {args.installer.name}\n"
        f"{sha256(args.output)}  {args.output.name}\n"
        f"{payload['sbom']['sha256']}  {args.sbom.name}\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
