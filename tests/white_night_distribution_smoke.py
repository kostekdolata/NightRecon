"""Build and verify the isolated White Night foundation distributions."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import venv
import zipfile


REPOSITORY = Path(__file__).resolve().parents[1]
WHITE_VERSION = "0.1.0a2"
SHARED_CORE_VERSION = "0.41.0"


def check(*args: str, cwd: Path) -> str:
    completed = subprocess.run(
        args,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if completed.returncode:
        raise AssertionError(
            f"Command {args[0]} failed ({completed.returncode}): "
            f"{completed.stdout[-1500:]} {completed.stderr[-1500:]}"
        )
    return completed.stdout


def scripts(directory: Path) -> tuple[Path, Path]:
    bin_dir = directory / ("Scripts" if os.name == "nt" else "bin")
    python = bin_dir / ("python.exe" if os.name == "nt" else "python")
    return bin_dir, python


def command(bin_dir: Path, name: str) -> str:
    return str(bin_dir / (name + (".exe" if os.name == "nt" else "")))


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="white-night-distribution-") as root:
        directory = Path(root)
        wheels = directory / "wheels"
        wheels.mkdir()

        for package in (
            REPOSITORY / "packages" / "shared-core",
            REPOSITORY / "packages" / "white-engine",
            REPOSITORY / "packages" / "white-night",
        ):
            check(
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--no-index",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                str(wheels),
                str(package),
                cwd=directory,
            )

        shared_core_wheel = next(
            wheels.glob(
                f"nightrecon_shared_core-{SHARED_CORE_VERSION}-*.whl"
            )
        )
        engine_wheel = next(
            wheels.glob(f"nightrecon_white_engine-{WHITE_VERSION}-*.whl")
        )
        app_wheel = next(
            wheels.glob(f"nightrecon_white_night-{WHITE_VERSION}-*.whl")
        )

        with zipfile.ZipFile(engine_wheel) as archive:
            engine_files = tuple(sorted(archive.namelist()))
        assert any(
            name.startswith("nightrecon_white_engine/") for name in engine_files
        )
        assert not any(
            name.startswith("nightrecon_red_engine/") for name in engine_files
        )
        assert not any(name.startswith("nightrecon/") for name in engine_files)

        with zipfile.ZipFile(app_wheel) as archive:
            app_files = tuple(sorted(archive.namelist()))
        assert any(name.startswith("white_night_app/") for name in app_files)
        assert not any(
            name.startswith("nightrecon_white_engine/") for name in app_files
        )
        assert not any(
            name.startswith("nightrecon_red_engine/") for name in app_files
        )
        assert not any(name.startswith("nightrecon/") for name in app_files)

        env_root = directory / "isolated"
        venv.create(env_root, with_pip=True)
        bin_dir, python = scripts(env_root)

        for wheel in (shared_core_wheel, engine_wheel, app_wheel):
            check(
                str(python),
                "-m",
                "pip",
                "install",
                "--no-index",
                "--no-deps",
                str(wheel),
                cwd=directory,
            )

        white_app = command(bin_dir, "white-night-app")
        help_text = check(white_app, "--help", cwd=directory)
        assert "White Night command boundary" in help_text
        assert "editions" in help_text
        for forbidden in (
            "scan",
            "discover",
            "infra",
            "crawl",
            "identity",
            "workspace",
        ):
            assert forbidden not in help_text

        catalog = json.loads(
            check(white_app, "editions", "--json", cwd=directory)
        )
        assert len(catalog) == 5
        white = next(item for item in catalog if item["name"] == "White Night")
        assert white["standalone_available"] is False

        denied = subprocess.run(
            [white_app, "scan"],
            cwd=directory,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        assert denied.returncode == 2, denied
        assert "Traceback" not in denied.stderr

        check(
            str(python),
            "-c",
            (
                "import importlib.util; "
                "import nightrecon_shared_core as core; "
                "import nightrecon_white_engine as engine; "
                "assert core.edition_name('white') == 'White Night'; "
                "assert engine.WHITE_OWNED_COMMANDS == ('editions',); "
                "assert engine.WHITE_ACTIVE_COMMANDS == (); "
                "assert importlib.util.find_spec('nightrecon') is None; "
                "assert importlib.util.find_spec('nightrecon_red_engine') is None"
            ),
            cwd=directory,
        )

        check(
            str(python),
            "-m",
            "white_night_app",
            "editions",
            "--json",
            cwd=directory,
        )

        metadata = check(
            str(python),
            "-c",
            (
                "import importlib.metadata as m; "
                "print(m.version('nightrecon-white-night')); "
                "print(m.version('nightrecon-white-engine')); "
                "print(m.version('nightrecon-shared-core')); "
                "print(m.requires('nightrecon-white-night'));"
            ),
            cwd=directory,
        )
        assert metadata.count(WHITE_VERSION) >= 2
        assert SHARED_CORE_VERSION in metadata
        assert "nightrecon-white-engine==0.1.0a2" in metadata
        assert "nightrecon-shared-core==0.41.0" in metadata
        assert "nightrecon-red" not in metadata
        assert "nightrecon==" not in metadata

        check(
            str(python),
            "-m",
            "pip",
            "uninstall",
            "--yes",
            "nightrecon-white-night",
            cwd=directory,
        )
        assert not Path(white_app).exists()
        check(
            str(python),
            "-c",
            (
                "import nightrecon_shared_core; "
                "import nightrecon_white_engine; "
                "assert nightrecon_shared_core is not None; "
                "assert nightrecon_white_engine is not None"
            ),
            cwd=directory,
        )

    print("White Night isolated distribution smoke: passed")


if __name__ == "__main__":
    main()
