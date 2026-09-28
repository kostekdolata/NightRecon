"""Run after installation to verify the generated Red Night console script."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def run(*args: str) -> subprocess.CompletedProcess[str]:
    executable = shutil.which("red-night")
    if executable is None:
        raise AssertionError("Installed red-night console script is missing")
    return subprocess.run(
        [executable, *args], capture_output=True, text=True, timeout=20,
        check=False,
    )


def main() -> None:
    import nightrecon_red_engine
    from nightrecon import software_identity as legacy_software_identity
    from nightrecon_red_engine import software_identity as canonical_software_identity

    assert nightrecon_red_engine.is_migrated_module("software_identity")
    assert (
        legacy_software_identity.SoftwareIdentity
        is canonical_software_identity.SoftwareIdentity
    )

    catalog = run("editions", "--json")
    assert catalog.returncode == 0, catalog.stderr
    entries = json.loads(catalog.stdout)
    assert [entry["name"] for entry in entries] == [
        "White Night", "Blue Night", "Red Night", "Purple Night", "Black Night",
    ]

    help_result = run("--help")
    assert help_result.returncode == 0, help_result.stderr
    assert "Red Night command boundary" in help_result.stdout

    denied = run("unknown-command")
    assert denied.returncode == 2, denied
    assert "Command is not available in this edition" in denied.stderr
    assert "Traceback" not in denied.stderr

    scan_help = run("scan", "--help")
    assert scan_help.returncode == 0, scan_help.stderr
    assert "--scope" in scan_help.stdout

    with tempfile.TemporaryDirectory(prefix="red-night-identity-") as directory:
        export = Path(directory) / "directory.json"
        export.write_text(json.dumps({"schema_version": 1, "entries": [
            {"dn": "CN=Operator,DC=example,DC=test", "kind": "user",
             "name": "Operator"},
        ]}), encoding="utf-8")
        imported = run("identity", "import", str(export),
                       "--source-id", "launcher-smoke")
        assert imported.returncode == 0, imported.stderr
        assert json.loads(imported.stdout)["identities"] == 1
        assert "graph" not in json.loads(imported.stdout)

    print("Red Night installed launcher smoke: passed")


if __name__ == "__main__":
    sys.exit(main())
