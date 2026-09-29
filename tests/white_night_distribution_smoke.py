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
WHITE_VERSION = "0.1.0a3"
SHARED_CORE_VERSION = "0.42.0"


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
        assert "policy" in help_text
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
                "assert engine.WHITE_OWNED_COMMANDS == ('editions', 'policy'); "
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

        check(
            str(python),
            "-c",
            (
                "from nightrecon_white_engine import "
                "DataHandlingPolicy, EngagementContact, EngagementDefinition, "
                "RulesOfEngagement, ScopeDefinition, render_rules_of_engagement; "
                "scope=ScopeDefinition(allowed=('192.0.2.0/24',), excluded=('192.0.2.250',)); "
                "roe=RulesOfEngagement("
                "engagement_id='eng-smoke', version=1, title='Packaged ROE', "
                "created_at='2026-09-29T12:00:00+00:00', "
                "valid_from='2026-10-01T08:00:00+00:00', "
                "valid_until='2026-10-02T18:00:00+00:00', scope=scope, "
                "allowed_techniques=('discovery',), max_actions=10, "
                "data_handling=DataHandlingPolicy()); "
                "contact=EngagementContact(contact_id='owner', display_name='Owner', role='lead'); "
                "eng=EngagementDefinition("
                "engagement_id='eng-smoke', version=1, name='Smoke', "
                "created_at='2026-09-29T12:00:00+00:00', status='planned', "
                "owner_contact_id='owner', contacts=(contact,), roe=roe); "
                "assert len(eng.fingerprint) == 64; "
                "assert 'does not itself authorize active operations' in render_rules_of_engagement(roe)"
            ),
            cwd=directory,
        )

        engagement_path = directory / "white-engagement.json"
        engagement_path.write_text(json.dumps({
            "schema_version": 1,
            "engagement_id": "eng-cli-smoke",
            "version": 1,
            "name": "CLI smoke",
            "created_at": "2026-09-29T12:00:00+00:00",
            "status": "planned",
            "owner_contact_id": "owner",
            "contacts": [{
                "contact_id": "owner",
                "display_name": "Owner",
                "role": "lead",
                "email": None,
                "phone": None,
            }],
            "roe": {
                "schema_version": 1,
                "engagement_id": "eng-cli-smoke",
                "version": 1,
                "title": "CLI smoke ROE",
                "created_at": "2026-09-29T12:00:00+00:00",
                "valid_from": "2026-10-01T08:00:00+00:00",
                "valid_until": "2026-10-02T18:00:00+00:00",
                "scope": {
                    "allowed": ["192.0.2.0/24"],
                    "excluded": ["192.0.2.250"],
                },
                "allowed_techniques": ["discovery"],
                "prohibited_techniques": [],
                "max_intrusiveness": "safe-active",
                "max_actions": 10,
                "data_handling": {
                    "classification": "confidential",
                    "retention_days": 90,
                    "export_allowed": True,
                    "notes": None,
                },
                "deviation_requires_approval": True,
                "notes": None,
            },
            "description": None,
        }, sort_keys=True), encoding="utf-8")
        bundle_path = directory / "compiled-policy.json"
        compiled = json.loads(check(
            white_app,
            "policy",
            "compile",
            str(engagement_path),
            "--output",
            str(bundle_path),
            cwd=directory,
        ))
        assert compiled["policy"]["max_impact"] == "standard"
        assert "192.0.2.250" not in compiled["policy"]["scope"]
        assert bundle_path.exists()
        verified = json.loads(check(
            white_app,
            "policy",
            "verify",
            str(bundle_path),
            cwd=directory,
        ))
        assert verified["integrity"] == "valid"
        assert verified["engagement_id"] == "eng-cli-smoke"

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
        assert "nightrecon-white-engine==0.1.0a3" in metadata
        assert "nightrecon-shared-core==0.42.0" in metadata
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
