"""Build four wheels and exercise separate and combined Red Night installations."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import venv
import zipfile


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
    standalone = {item["name"]: item["standalone_available"] for item in catalog}
    assert standalone["Red Night"] is True
    assert all(
        available is False
        for name, available in standalone.items()
        if name != "Red Night"
    )
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
    envelope = json.loads(check(
        app, "identity", "import", str(snapshot),
        "--source-id", "packaged-smoke",
        "--engagement-id", "eng-packaged-smoke",
        "--export-envelope",
        cwd=directory,
    ))
    assert envelope["schema_version"] == 1
    assert envelope["engagement_id"] == "eng-packaged-smoke"
    assert len(envelope["records"]) == 1
    record = envelope["records"][0]
    assert record["source_night"] == "red"
    assert record["evidence_type"] == "identity.directory-snapshot"
    assert record["data"]["identity_count"] == 1
    assert record["data"]["observed_membership_count"] == 0
    assert "No live directory collection performed" in record["limitations"]

    store_path = directory / f"engagement-store-{bin_dir.parent.name}.json"
    persisted = json.loads(check(
        app, "identity", "import", str(snapshot),
        "--source-id", "packaged-smoke-store",
        "--engagement-id", "eng-packaged-smoke",
        "--store", str(store_path),
        cwd=directory,
    ))
    assert persisted["identities"] == 1
    assert store_path.exists()

    stored = json.loads(check(
        app, "identity", "store-list", str(store_path),
        "--engagement-id", "eng-packaged-smoke",
        "--source-night", "red",
        "--evidence-type", "identity.directory-snapshot",
        cwd=directory,
    ))
    assert stored["engagement_id"] == "eng-packaged-smoke"
    assert len(stored["records"]) == 1
    assert stored["records"][0]["source_night"] == "red"

    metadata = json.loads(check(
        app, "identity", "store-metadata", str(store_path),
        "--engagement-id", "eng-packaged-smoke",
        "--name", "Packaged smoke engagement",
        "--authorization-reference", "approval://packaged-smoke",
        "--status", "active",
        cwd=directory,
    ))
    assert metadata["engagement_id"] == "eng-packaged-smoke"
    assert metadata["authorization_reference"] == "approval://packaged-smoke"

    export_path = directory / f"engagement-export-{bin_dir.parent.name}.json"
    exported = json.loads(check(
        app, "identity", "store-export", str(store_path),
        "--engagement-id", "eng-packaged-smoke",
        "--output", str(export_path),
        cwd=directory,
    ))
    assert exported["records"] == 1
    exported_envelope = json.loads(export_path.read_text(encoding="utf-8"))
    assert exported_envelope["metadata"]["name"] == "Packaged smoke engagement"

    imported_store = directory / f"engagement-import-{bin_dir.parent.name}.json"
    imported_store_result = json.loads(check(
        app, "identity", "store-import", str(imported_store), str(export_path),
        cwd=directory,
    ))
    assert imported_store_result["engagement_id"] == "eng-packaged-smoke"
    assert imported_store_result["source_nights"] == ["red"]
    imported_envelope = json.loads(check(
        app, "identity", "store-list", str(imported_store),
        "--engagement-id", "eng-packaged-smoke",
        cwd=directory,
    ))
    assert imported_envelope["metadata"]["authorization_reference"] == "approval://packaged-smoke"
    assert len(imported_envelope["records"]) == 1

    workspace_root = directory / f"workspace-{bin_dir.parent.name}"
    created_workspace = json.loads(check(
        app, "workspace", "create", str(workspace_root),
        "--engagement-id", "eng-workspace-life",
        "--name", "Packaged workspace lifecycle",
        "--authorization-reference", "approval://workspace-life",
        cwd=directory,
    ))
    assert created_workspace["status"] == "planned"
    active_workspace = json.loads(check(
        app, "workspace", "status", str(workspace_root),
        "--engagement-id", "eng-workspace-life", "--set", "active",
        cwd=directory,
    ))
    assert active_workspace["status"] == "active"

    policy = json.loads(check(
        app, "workspace", "policy-set", str(workspace_root),
        "--engagement-id", "eng-workspace-life",
        "--scope", "192.0.2.0/24",
        "--valid-from", "2026-01-01T00:00:00+00:00",
        "--valid-until", "2030-01-01T00:00:00+00:00",
        "--max-actions", "2",
        "--capability", "discovery",
        "--capability", "validation",
        "--approval-required", "validation",
        cwd=directory,
    ))
    assert policy["max_actions"] == 2
    denied_policy = json.loads(check(
        app, "workspace", "authorize", str(workspace_root),
        "--engagement-id", "eng-workspace-life",
        "--capability", "discovery", "--target", "198.51.100.1",
        cwd=directory,
    ))
    assert denied_policy["allowed"] is False
    assert denied_policy["reason_code"] == "target_out_of_scope"
    allowed_policy = json.loads(check(
        app, "workspace", "authorize", str(workspace_root),
        "--engagement-id", "eng-workspace-life",
        "--capability", "discovery", "--target", "192.0.2.10", "--consume",
        cwd=directory,
    ))
    assert allowed_policy["allowed"] is True
    assert allowed_policy["actions_used"] == 1
    audit_policy = json.loads(check(
        app, "workspace", "audit", str(workspace_root),
        "--engagement-id", "eng-workspace-life",
        cwd=directory,
    ))
    assert [item["reason_code"] for item in audit_policy] == [
        "target_out_of_scope", "authorized",
    ]

    workspace_import = json.loads(check(
        app, "workspace", "import", str(workspace_root), str(export_path),
        cwd=directory,
    ))
    assert workspace_import["applied"] is True
    workspace_list = json.loads(check(
        app, "workspace", "list", str(workspace_root), cwd=directory,
    ))
    by_engagement = {item["engagement_id"]: item for item in workspace_list}
    assert set(by_engagement) == {"eng-workspace-life", "eng-packaged-smoke"}
    assert by_engagement["eng-workspace-life"]["status"] == "active"
    assert by_engagement["eng-packaged-smoke"]["source_nights"] == ["red"]
    workspace_show = json.loads(check(
        app, "workspace", "show", str(workspace_root),
        "--engagement-id", "eng-packaged-smoke",
        cwd=directory,
    ))
    assert workspace_show["summary"]["record_count"] == 1
    assert workspace_show["breakdown"]["source_night_counts"] == [["red", 1]]
    workspace_timeline = json.loads(check(
        app, "workspace", "timeline", str(workspace_root),
        "--engagement-id", "eng-packaged-smoke", cwd=directory,
    ))
    assert len(workspace_timeline) == 1
    assert workspace_timeline[0]["evidence_type"] == "identity.directory-snapshot"
    workspace_export_path = directory / f"workspace-export-{bin_dir.parent.name}.json"
    workspace_export = json.loads(check(
        app, "workspace", "export", str(workspace_root),
        "--engagement-id", "eng-packaged-smoke",
        "--output", str(workspace_export_path),
        cwd=directory,
    ))
    assert workspace_export["source_nights"] == ["red"]
    assert json.loads(workspace_export_path.read_text(encoding="utf-8"))["engagement_id"] == "eng-packaged-smoke"

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
            REPOSITORY / "packages" / "red-engine",
            REPOSITORY / "packages" / "red-night",
        ):
            check(
                sys.executable, "-m", "pip", "wheel", "--no-index",
                "--no-deps", "--no-build-isolation", "--wheel-dir", str(wheels),
                str(package), cwd=directory,
            )
        core_wheel = next(wheels.glob("nightrecon-0.31.0-*.whl"))
        shared_core_wheel = next(
            wheels.glob("nightrecon_shared_core-0.34.0.dev0-*.whl")
        )
        red_engine_wheel = next(
            wheels.glob("nightrecon_red_engine-0.34.0.dev0-*.whl")
        )
        app_wheel = next(wheels.glob("nightrecon_red_night-0.34.0.dev0-*.whl"))

        with zipfile.ZipFile(app_wheel) as archive:
            app_files = tuple(sorted(archive.namelist()))
        assert any(name.startswith("red_night_app/") for name in app_files)
        assert not any(name.startswith("nightrecon_red_engine/") for name in app_files)
        assert not any(name.startswith("nightrecon/") for name in app_files), app_files

        with zipfile.ZipFile(red_engine_wheel) as archive:
            engine_files = tuple(sorted(archive.namelist()))
        assert any(name.startswith("nightrecon_red_engine/") for name in engine_files)
        assert not any(name.startswith("nightrecon/") for name in engine_files), engine_files

        for mode in ("isolated", "combined"):
            env_root = directory / mode
            venv.create(env_root, with_pip=True, system_site_packages=True)
            bin_dir, python = scripts(env_root)
            check(str(python), "-m", "pip", "install", "--no-index",
                  "--no-deps", str(shared_core_wheel), cwd=directory)
            check(str(python), "-m", "pip", "install", "--no-index",
                  "--no-deps", str(red_engine_wheel), cwd=directory)
            check(
                str(python), "-c",
                "from nightrecon_red_engine import host_discovery, resolver, service_probe, "
                "session, software_identity, tcp_scanner, tls_detection; "
                "assert software_identity.SoftwareIdentity.__name__ == 'SoftwareIdentity'; "
                "assert host_discovery.HostDiscoveryResult.__name__ == 'HostDiscoveryResult'; "
                "assert resolver.ResolutionResult.__name__ == 'ResolutionResult'; "
                "assert service_probe.ServiceProbeDefinition.__name__ == 'ServiceProbeDefinition'; "
                "assert session.ScanSession.__name__ == 'ScanSession'; "
                "assert tcp_scanner.TcpPortResult.__name__ == 'TcpPortResult'; "
                "assert tls_detection.TlsMetadata.__name__ == 'TlsMetadata'",
                cwd=directory,
            )
            if mode == "isolated":
                check(
                    str(python), "-c",
                    "import importlib.util; "
                    "assert importlib.util.find_spec('nightrecon') is None",
                    cwd=directory,
                )
            if mode == "combined" or arguments.offline_host_dependencies:
                check(str(python), "-m", "pip", "install", "--no-index",
                      "--no-deps", str(core_wheel), cwd=directory)
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
            if mode == "isolated" or arguments.offline_host_dependencies:
                install_args.append("--no-deps")
            else:
                install_args.extend(("--find-links", str(wheels)))
            check(*install_args, str(app_wheel), cwd=directory)
            verify_app(bin_dir, directory)

            if mode == "isolated":
                check(
                    str(python), "-c",
                    "import importlib.util; "
                    "assert importlib.util.find_spec('nightrecon') is None; "
                    "from nightrecon_red_engine.red_cli import main; "
                    "assert callable(main)",
                    cwd=directory,
                )
            else:
                check(
                    str(python), "-c",
                    "import nightrecon_red_engine as e; "
                    "import nightrecon.software_identity as legacy; "
                    "from nightrecon_red_engine import software_identity as canonical; "
                    "assert e.NAMESPACE == 'nightrecon_red_engine'; "
                    "assert e.LEGACY_NAMESPACE == 'nightrecon'; "
                    "assert e.existing_module('software_identity') is canonical; "
                    "assert legacy.SoftwareIdentity is canonical.SoftwareIdentity; "
                    "import nightrecon.host_discovery as legacy_hd; "
                    "from nightrecon_red_engine import host_discovery as canonical_hd; "
                    "assert e.is_migrated_module('host_discovery'); "
                    "assert legacy_hd is canonical_hd",
                    cwd=directory,
                )

            metadata_script = (
                "import importlib.metadata as m; "
                "print(m.version('nightrecon-red-night')); "
                "print(m.version('nightrecon-red-engine')); "
                "print(m.version('nightrecon-shared-core')); "
                "print(m.requires('nightrecon-red-night')); "
            )
            if mode == "combined":
                metadata_script += "print(m.version('nightrecon')); "
            metadata = check(str(python), "-c", metadata_script, cwd=directory)
            if mode == "combined":
                assert "0.31.0" in metadata
            assert metadata.count("0.34.0.dev0") >= 3
            assert "nightrecon==0.31.0" not in metadata
            assert "nightrecon-red-engine==0.34.0.dev0" in metadata
            assert "nightrecon-shared-core==0.34.0.dev0" in metadata
            assert "cryptography" in metadata
            for extra_dependency in (
                "playwright", "PyYAML", "paramiko", "impacket", "pywinrm",
                "psycopg", "mysql-connector-python",
            ):
                assert extra_dependency in metadata
            check(str(python), "-m", "red_night_app", "--help", cwd=directory)

            if mode == "combined":
                check(str(python), "-m", "pip", "uninstall", "--yes",
                      "nightrecon-red-night", cwd=directory)
                assert "Red Night command boundary" in check(
                    command(bin_dir, "red-night"), "--help", cwd=directory,
                )
                assert not Path(command(bin_dir, "red-night-app")).exists()
                check(
                    str(python), "-c",
                    "import nightrecon; import nightrecon_red_engine; "
                    "assert nightrecon is not None; "
                    "assert nightrecon_red_engine is not None",
                    cwd=directory,
                )

    print("Red Night separate-distribution installations: passed")


if __name__ == "__main__":
    main()
