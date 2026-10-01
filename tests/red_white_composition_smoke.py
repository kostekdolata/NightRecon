"""Red + White normal-install composition and isolation smoke.

This is the first Red v0.44 Batch 5 composition gate.  It proves that both
Night applications can share one compatible shared-core installation without
cross-engine runtime coupling, and that removing either Night leaves the other
usable.
"""

from __future__ import annotations

import ast
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import venv


REPOSITORY = Path(__file__).resolve().parents[1]
SHARED_CORE_VERSION = "0.43.0"
RED_VERSION = "0.43.0"
WHITE_VERSION = "0.1.0a6"


def run(
    *args: str,
    cwd: Path,
    timeout: int = 180,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        args,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if check and completed.returncode:
        raise AssertionError(
            f"Command {args[0]} failed ({completed.returncode}): "
            f"{completed.stdout[-2000:]} {completed.stderr[-2000:]}"
        )
    return completed


def scripts(directory: Path) -> tuple[Path, Path]:
    bin_dir = directory / ("Scripts" if os.name == "nt" else "bin")
    python = bin_dir / ("python.exe" if os.name == "nt" else "python")
    return bin_dir, python


def command(bin_dir: Path, name: str) -> str:
    return str(bin_dir / (name + (".exe" if os.name == "nt" else "")))


def privileged_command(*args: str) -> tuple[str, ...]:
    if os.name == "nt":
        return tuple(args)
    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None and geteuid() == 0:
        return tuple(args)
    sudo = shutil.which("sudo")
    if sudo is None:
        raise AssertionError("Red composition smoke requires sudo on POSIX")
    return (sudo, "--", *args)


def assert_no_cross_engine_imports() -> None:
    forbidden = (
        (REPOSITORY / "packages" / "red-night", "nightrecon_white_engine"),
        (REPOSITORY / "packages" / "red-engine", "nightrecon_white_engine"),
        (REPOSITORY / "packages" / "white-night", "nightrecon_red_engine"),
        (REPOSITORY / "packages" / "white-engine", "nightrecon_red_engine"),
    )
    for root, forbidden_module in forbidden:
        for path in root.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                imported: tuple[str, ...] = ()
                if isinstance(node, ast.Import):
                    imported = tuple(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom):
                    imported = ((node.module or ""),)
                if any(
                    name == forbidden_module
                    or name.startswith(forbidden_module + ".")
                    for name in imported
                ):
                    raise AssertionError(
                        f"Cross-engine import {forbidden_module!r} found in {path}"
                    )


def build_wheels(directory: Path) -> dict[str, Path]:
    wheel_dir = directory / "wheels"
    wheel_dir.mkdir()
    for package in (
        REPOSITORY / "packages" / "shared-core",
        REPOSITORY / "packages" / "red-engine",
        REPOSITORY / "packages" / "red-night",
        REPOSITORY / "packages" / "white-engine",
        REPOSITORY / "packages" / "white-night",
    ):
        run(
            sys.executable,
            "-m",
            "pip",
            "wheel",
            "--no-index",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheel_dir),
            str(package),
            cwd=directory,
        )

    return {
        "shared": next(
            wheel_dir.glob(f"nightrecon_shared_core-{SHARED_CORE_VERSION}-*.whl")
        ),
        "red_engine": next(
            wheel_dir.glob(f"nightrecon_red_engine-{RED_VERSION}-*.whl")
        ),
        "red_app": next(
            wheel_dir.glob(f"nightrecon_red_night-{RED_VERSION}-*.whl")
        ),
        "white_engine": next(
            wheel_dir.glob(f"nightrecon_white_engine-{WHITE_VERSION}-*.whl")
        ),
        "white_app": next(
            wheel_dir.glob(f"nightrecon_white_night-{WHITE_VERSION}-*.whl")
        ),
    }


def install(python: Path, directory: Path, *wheels: Path) -> None:
    if not wheels:
        return

    wheel_dir = wheels[0].parent
    run(
        str(python),
        "-m",
        "pip",
        "install",
        "--find-links",
        str(wheel_dir),
        *(str(wheel) for wheel in wheels),
        cwd=directory,
    )


def uninstall(python: Path, directory: Path, *packages: str) -> None:
    run(
        str(python),
        "-m",
        "pip",
        "uninstall",
        "-y",
        *packages,
        cwd=directory,
    )


def verify_both(bin_dir: Path, python: Path, directory: Path) -> None:
    red_app = command(bin_dir, "red-night-app")
    white_app = command(bin_dir, "white-night-app")

    run(*privileged_command(red_app, "--help"), cwd=directory)

    white_help = run(white_app, "--help", cwd=directory).stdout
    if "White Night command boundary" not in white_help:
        raise AssertionError("White app did not expose its packaged command boundary")

    run(
        str(python),
        "-c",
        (
            "import nightrecon_shared_core as core; "
            "import nightrecon_red_engine as red; "
            "import nightrecon_white_engine as white; "
            "assert core.edition_name('red') == 'Red Night'; "
            "assert core.edition_name('white') == 'White Night'; "
            "assert red is not None; assert white is not None"
        ),
        cwd=directory,
    )


def verify_shared_workspace_exchange(
    python: Path,
    directory: Path,
) -> None:
    run(
        str(python),
        "-c",
        (
            "import tempfile; "
            "from pathlib import Path; "
            "from nightrecon_shared_core.contracts import "
            "EngagementEnvelope, EngagementMetadata, EvidenceRecord; "
            "from nightrecon_shared_core.workspace import LocalWorkspace; "
            "root = Path(tempfile.mkdtemp(prefix='red-white-workspace-')); "
            "workspace = LocalWorkspace(root); "
            "metadata = EngagementMetadata("
            "engagement_id='eng-composed', name='Composed lab', "
            "created_at='2026-10-01T00:00:00+00:00', "
            "authorization_reference='approval://eng-composed', status='active'); "
            "red = EvidenceRecord("
            "engagement_id='eng-composed', evidence_id='red-1', source_night='red', "
            "evidence_type='asset.observation', observed_at='2026-10-01T00:01:00+00:00', "
            "provenance='red://fixture/asset-1', data={'asset_id':'asset-1'}, "
            "limitations=('red fixture only',)); "
            "white = EvidenceRecord("
            "engagement_id='eng-composed', evidence_id='white-1', source_night='white', "
            "evidence_type='authorization.observation', observed_at='2026-10-01T00:02:00+00:00', "
            "provenance='white://fixture/approval-1', data={'approval_ref':'approval-1'}, "
            "limitations=('white fixture only',)); "
            "assert workspace.merge_envelope(EngagementEnvelope("
            "engagement_id='eng-composed', metadata=metadata, records=(red,))).applied; "
            "assert workspace.merge_envelope(EngagementEnvelope("
            "engagement_id='eng-composed', metadata=metadata, records=(white,))).applied; "
            "reopened = LocalWorkspace(root); "
            "envelope = reopened.envelope('eng-composed'); "
            "assert tuple(r.source_night for r in envelope.records) == ('red','white'); "
            "assert {r.provenance for r in envelope.records} == "
            "{'red://fixture/asset-1','white://fixture/approval-1'}; "
            "assert {r.limitations for r in envelope.records} == "
            "{('red fixture only',),('white fixture only',)}; "
            "future = envelope.to_dict(); future['schema_version'] = 2; "
            "failed_closed = False; "
            "try:\n EngagementEnvelope.from_dict(future)\n"
            "except ValueError:\n failed_closed = True\n"
            "assert failed_closed"
        ),
        cwd=directory,
    )


def verify_red_survives_white_removal(
    bin_dir: Path,
    python: Path,
    directory: Path,
) -> None:
    uninstall(
        python,
        directory,
        "nightrecon-white-night",
        "nightrecon-white-engine",
    )
    run(
        str(python),
        "-c",
        (
            "import importlib.util; import nightrecon_shared_core; "
            "import nightrecon_red_engine; "
            "assert importlib.util.find_spec('nightrecon_white_engine') is None"
        ),
        cwd=directory,
    )
    red_app = command(bin_dir, "red-night-app")
    run(*privileged_command(red_app, "--help"), cwd=directory)


def verify_white_survives_red_removal(
    bin_dir: Path,
    python: Path,
    directory: Path,
) -> None:
    uninstall(
        python,
        directory,
        "nightrecon-red-night",
        "nightrecon-red-engine",
    )
    run(
        str(python),
        "-c",
        (
            "import importlib.util; import nightrecon_shared_core; "
            "import nightrecon_white_engine; "
            "assert importlib.util.find_spec('nightrecon_red_engine') is None"
        ),
        cwd=directory,
    )
    white_app = command(bin_dir, "white-night-app")
    run(white_app, "--help", cwd=directory)


def main() -> None:
    assert_no_cross_engine_imports()

    with tempfile.TemporaryDirectory(prefix="red-white-composition-") as root:
        directory = Path(root)
        wheels = build_wheels(directory)

        env_root = directory / "composed"
        venv.create(env_root, with_pip=True)
        bin_dir, python = scripts(env_root)

        install(
            python,
            directory,
            wheels["shared"],
            wheels["red_engine"],
            wheels["red_app"],
            wheels["white_engine"],
            wheels["white_app"],
        )
        verify_both(bin_dir, python, directory)
        verify_shared_workspace_exchange(python, directory)

        verify_red_survives_white_removal(bin_dir, python, directory)

        install(
            python,
            directory,
            wheels["white_engine"],
            wheels["white_app"],
        )
        verify_both(bin_dir, python, directory)

        verify_white_survives_red_removal(bin_dir, python, directory)

        run(
            str(python),
            "-c",
            (
                "import nightrecon_shared_core; "
                "assert nightrecon_shared_core is not None"
            ),
            cwd=directory,
        )

    print("RED_WHITE_COMPOSITION_OK")


if __name__ == "__main__":
    main()
