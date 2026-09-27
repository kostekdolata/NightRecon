"""Build two wheels and exercise separate and combined Red Night installations."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import venv


REPOSITORY = Path(__file__).resolve().parents[1]


def check(*args: str, cwd: Path, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        args, cwd=cwd, env=env, capture_output=True, text=True, timeout=120,
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
    return bin_dir, bin_dir / ("python.exe" if os.name == "nt" else "python")


def command(bin_dir: Path, name: str) -> str:
    return str(bin_dir / (name + (".exe" if os.name == "nt" else "")))


def verify_app(bin_dir: Path, directory: Path) -> None:
    app = command(bin_dir, "red-night-app")
    help_text = check(app, "--help", cwd=directory)
    assert "Red Night command boundary" in help_text
    assert "scan" in help_text
    catalog = json.loads(check(app, "editions", "--json", cwd=directory))
    assert len(catalog) == 5
    assert all(not item["standalone_available"] for item in catalog)
    assert "--scope" in check(app, "scan", "--help", cwd=directory)
    snapshot = directory / "directory-export.json"
    snapshot.write_text(json.dumps({
        "schema_version": 1,
        "entries": [
            {"dn": "CN=Operator,DC=example,DC=test", "kind": "user",
             "name": "Operator"},
        ],
    }), encoding="utf-8")
    imported = json.loads(check(
        app, "identity", "import", str(snapshot), "--source-id", "packaged-smoke",
        cwd=directory,
    ))
    assert imported["identities"] == 1
    assert "graph" not in imported
    assert imported["observed_memberships"] == 0
    denied = subprocess.run(
        [app, "unknown-command"], cwd=directory, capture_output=True,
        text=True, timeout=20, check=False,
    )
    assert denied.returncode == 2, denied
    assert "Command is not available in this edition" in denied.stderr
    assert "Traceback" not in denied.stderr


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--offline-host-dependencies", action="store_true",
        help="Use preinstalled host libraries for local smoke when no matching wheel is cached.",
    )
    arguments = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="red-night-distribution-") as root:
        directory = Path(root)
        wheels = directory / "wheels"
        wheels.mkdir()
        for package in (
            REPOSITORY,
            REPOSITORY / "packages" / "shared-core",
            REPOSITORY / "packages" / "red-night",
        ):
            check(
                sys.executable, "-m", "pip", "wheel", "--no-index",
                "--no-deps", "--no-build-isolation", "--wheel-dir", str(wheels),
                str(package), cwd=directory,
            )
        core_wheel = next(wheels.glob("nightrecon-0.31.0-*.whl"))
        shared_core_wheel = next(
            wheels.glob("nightrecon_shared_core-0.32.0.dev0-*.whl")
        )
        app_wheel = next(wheels.glob("nightrecon_red_night-0.32.0.dev0-*.whl"))

        for mode in ("isolated", "combined"):
            env_root = directory / mode
            venv.create(env_root, with_pip=True, system_site_packages=True)
            bin_dir, python = scripts(env_root)
            if mode == "combined" or arguments.offline_host_dependencies:
                check(str(python), "-m", "pip", "install", "--no-index",
                      "--no-deps", str(core_wheel), cwd=directory)
            check(str(python), "-m", "pip", "install", "--no-index",
                  "--no-deps", str(shared_core_wheel), cwd=directory)
            check(
                str(python), "-c",
                "import nightrecon_shared_core as c; "
                "assert c.edition_name('red') == 'Red Night'; "
                "assert c.Scope.from_values(['192.0.2.0/24']).is_authorized("
                "c.parse_target('192.0.2.10'))",
                cwd=directory,
            )
            if mode == "combined":
                assert "Red Night command boundary" in check(
                    command(bin_dir, "red-night"), "--help", cwd=directory,
                )

            install_args = [str(python), "-m", "pip", "install", "--no-index"]
            if arguments.offline_host_dependencies:
                install_args.append("--no-deps")
            else:
                install_args.extend(("--find-links", str(wheels)))
            check(*install_args, str(app_wheel), cwd=directory)
            verify_app(bin_dir, directory)

            metadata = check(
                str(python), "-c",
                "import importlib.metadata as m; "
                "print(m.version('nightrecon')); "
                "print(m.version('nightrecon-red-night')); "
                "print(m.version('nightrecon-shared-core')); "
                "print(m.requires('nightrecon-red-night'))",
                cwd=directory,
            )
            assert "0.31.0" in metadata
            assert metadata.count("0.32.0.dev0") >= 2
            assert "nightrecon==0.31.0" in metadata
            assert "nightrecon-shared-core==0.32.0.dev0" in metadata
            check(str(python), "-m", "red_night_app", "--help", cwd=directory)

            if mode == "combined":
                check(str(python), "-m", "pip", "uninstall", "--yes",
                      "nightrecon-red-night", cwd=directory)
                assert "Red Night command boundary" in check(
                    command(bin_dir, "red-night"), "--help", cwd=directory,
                )
                assert not Path(command(bin_dir, "red-night-app")).exists()

    print("Red Night separate-distribution installations: passed")


if __name__ == "__main__":
    main()
