"""Cross-platform packaged Red Night install/upgrade/uninstall/rollback smoke."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import venv


REPOSITORY = Path(__file__).resolve().parents[1]
BASELINE_VERSION = "0.43.0"
CANDIDATE_VERSION = "0.43.0.post1"
PACKAGE_DIRS = (
    ("shared-core", "nightrecon_shared_core"),
    ("red-engine", "nightrecon_red_engine"),
    ("red-night", "nightrecon_red_night"),
)


def check(*args: str, cwd: Path) -> str:
    completed = subprocess.run(
        args,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    if completed.returncode:
        raise AssertionError(
            f"Command {args[0]} failed ({completed.returncode}): "
            f"{completed.stdout[-2000:]} {completed.stderr[-2000:]}"
        )
    return completed.stdout


def scripts(directory: Path) -> tuple[Path, Path]:
    bin_dir = directory / ("Scripts" if os.name == "nt" else "bin")
    return bin_dir, bin_dir / ("python.exe" if os.name == "nt" else "python")


def wheel_for(wheels: Path, normalized_name: str, version: str) -> Path:
    matches = tuple(wheels.glob(f"{normalized_name}-{version}-*.whl"))
    if len(matches) != 1:
        raise AssertionError(
            f"expected exactly one {normalized_name} {version} wheel, found {matches}"
        )
    return matches[0]


def build_wheels(source_root: Path, wheels: Path, *, python: str) -> None:
    for package in (
        source_root / "packages" / "shared-core",
        source_root / "packages" / "red-engine",
        source_root / "packages" / "red-night",
    ):
        check(
            python,
            "-m",
            "pip",
            "wheel",
            "--no-index",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheels),
            str(package),
            cwd=source_root,
        )


def make_candidate_source(destination: Path) -> Path:
    candidate = destination / "candidate-source"
    (candidate / "packages").mkdir(parents=True)
    for directory, _ in PACKAGE_DIRS:
        shutil.copytree(
            REPOSITORY / "packages" / directory,
            candidate / "packages" / directory,
        )

    for relative in (
        Path("packages/shared-core/pyproject.toml"),
        Path("packages/red-engine/pyproject.toml"),
        Path("packages/red-night/pyproject.toml"),
    ):
        path = candidate / relative
        text = path.read_text(encoding="utf-8")
        if BASELINE_VERSION not in text:
            raise AssertionError(f"baseline version missing from {relative}")
        path.write_text(
            text.replace(BASELINE_VERSION, CANDIDATE_VERSION),
            encoding="utf-8",
        )

    composition = candidate / "packages/red-night/red_night_app/composition.py"
    text = composition.read_text(encoding="utf-8")
    marker = f'RED_STACK_VERSION = "{BASELINE_VERSION}"'
    if marker not in text:
        raise AssertionError("candidate composition version marker not found")
    composition.write_text(
        text.replace(
            marker,
            f'RED_STACK_VERSION = "{CANDIDATE_VERSION}"',
        ),
        encoding="utf-8",
    )
    return candidate


def install_stack(
    python: Path,
    wheels: Path,
    version: str,
    *,
    upgrade: bool = False,
    force_reinstall: bool = False,
) -> None:
    args = [
        str(python),
        "-m",
        "pip",
        "install",
        "--no-index",
        "--no-deps",
    ]
    if upgrade:
        args.append("--upgrade")
    if force_reinstall:
        args.append("--force-reinstall")
    args.extend((
        str(wheel_for(wheels, "nightrecon_shared_core", version)),
        str(wheel_for(wheels, "nightrecon_red_engine", version)),
        str(wheel_for(wheels, "nightrecon_red_night", version)),
    ))
    check(*args, cwd=wheels)


def installed_versions(python: Path, cwd: Path) -> tuple[str, str, str]:
    output = check(
        str(python),
        "-c",
        (
            "import importlib.metadata as m; "
            "print(m.version('nightrecon-shared-core')); "
            "print(m.version('nightrecon-red-engine')); "
            "print(m.version('nightrecon-red-night'))"
        ),
        cwd=cwd,
    )
    return tuple(output.strip().splitlines())  # type: ignore[return-value]


def create_workspace(python: Path, workspace: Path, cwd: Path) -> None:
    script = """
from nightrecon_shared_core.contracts import EngagementMetadata
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy
from nightrecon_shared_core.workspace import LocalWorkspace

workspace = LocalWorkspace(r'''%s''')
workspace.create_engagement(EngagementMetadata(
    engagement_id='lifecycle-engagement',
    name='Lifecycle acceptance',
    created_at='2026-10-03T00:00:00+00:00',
    authorization_reference='approval://lifecycle-fixture',
    status='active',
))
workspace.set_execution_policy(EngagementExecutionPolicy(
    engagement_id='lifecycle-engagement',
    scope=('192.0.2.0/24',),
    valid_from='2026-10-03T00:00:00+00:00',
    valid_until='2030-01-01T00:00:00+00:00',
    max_actions=3,
    permitted_capabilities=('discovery',),
))
decision = workspace.authorize_action(
    'lifecycle-engagement',
    capability='discovery',
    target='192.0.2.10',
    consume=True,
)
assert decision.allowed
""" % str(workspace)
    check(str(python), "-c", script, cwd=cwd)


def assert_workspace_preserved(python: Path, workspace: Path, cwd: Path) -> None:
    script = """
from nightrecon_shared_core.workspace import LocalWorkspace

workspace = LocalWorkspace(r'''%s''')
summary = workspace.summary('lifecycle-engagement')
policy = workspace.execution_policy('lifecycle-engagement')
audit = workspace.authorization_audit('lifecycle-engagement')
assert summary.status == 'active'
assert policy.actions_used == 1
assert policy.max_actions == 3
assert policy.scope == ('192.0.2.0/24',)
assert len(audit) == 1
assert audit[0].allowed is True
""" % str(workspace)
    check(str(python), "-c", script, cwd=cwd)


def assert_stack_compatible(python: Path, expected: str, cwd: Path) -> None:
    script = (
        "import importlib.metadata as m; "
        "from red_night_app.composition import evaluate_red_composition_compatibility; "
        "versions={name:m.version(name) for name in "
        "('nightrecon-shared-core','nightrecon-red-engine','nightrecon-red-night')}; "
        f"assert set(versions.values()) == {{{expected!r}}}; "
        "result=evaluate_red_composition_compatibility(versions); "
        "assert result.compatible, result"
    )
    check(str(python), "-c", script, cwd=cwd)


def main() -> None:
    argparse.ArgumentParser().parse_args()

    with tempfile.TemporaryDirectory(prefix="red-night-lifecycle-") as temp:
        root = Path(temp)
        baseline_wheels = root / "baseline-wheels"
        candidate_wheels = root / "candidate-wheels"
        baseline_wheels.mkdir()
        candidate_wheels.mkdir()

        build_wheels(REPOSITORY, baseline_wheels, python=sys.executable)
        candidate_source = make_candidate_source(root)
        build_wheels(candidate_source, candidate_wheels, python=sys.executable)

        environment = root / "venv"
        venv.create(environment, with_pip=True, system_site_packages=True)
        bin_dir, python = scripts(environment)
        workspace = root / "persistent-workspace"

        # Clean baseline installation.
        install_stack(python, baseline_wheels, BASELINE_VERSION)
        assert installed_versions(python, root) == (
            BASELINE_VERSION,
            BASELINE_VERSION,
            BASELINE_VERSION,
        )
        assert_stack_compatible(python, BASELINE_VERSION, root)
        create_workspace(python, workspace, root)
        assert_workspace_preserved(python, workspace, root)

        # Upgrade all three Red stack packages together.
        install_stack(
            python,
            candidate_wheels,
            CANDIDATE_VERSION,
            upgrade=True,
        )
        assert installed_versions(python, root) == (
            CANDIDATE_VERSION,
            CANDIDATE_VERSION,
            CANDIDATE_VERSION,
        )
        assert_stack_compatible(python, CANDIDATE_VERSION, root)
        assert_workspace_preserved(python, workspace, root)

        # Removing the application must not remove engine/shared-core or workspace.
        check(
            str(python),
            "-m",
            "pip",
            "uninstall",
            "--yes",
            "nightrecon-red-night",
            cwd=root,
        )
        check(
            str(python),
            "-c",
            (
                "import importlib.util, importlib.metadata as m; "
                "assert importlib.util.find_spec('red_night_app') is None; "
                f"assert m.version('nightrecon-red-engine') == {CANDIDATE_VERSION!r}; "
                f"assert m.version('nightrecon-shared-core') == {CANDIDATE_VERSION!r}"
            ),
            cwd=root,
        )
        assert_workspace_preserved(python, workspace, root)

        # Reinstall candidate application without mutating persistent workspace.
        check(
            str(python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            str(wheel_for(candidate_wheels, "nightrecon_red_night", CANDIDATE_VERSION)),
            cwd=root,
        )
        assert_stack_compatible(python, CANDIDATE_VERSION, root)
        assert_workspace_preserved(python, workspace, root)

        # Roll back the exact package set and prove state remains intact.
        install_stack(
            python,
            baseline_wheels,
            BASELINE_VERSION,
            force_reinstall=True,
        )
        assert installed_versions(python, root) == (
            BASELINE_VERSION,
            BASELINE_VERSION,
            BASELINE_VERSION,
        )
        assert_stack_compatible(python, BASELINE_VERSION, root)
        assert_workspace_preserved(python, workspace, root)

        # A mixed stack must fail closed.
        check(
            str(python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--force-reinstall",
            str(wheel_for(candidate_wheels, "nightrecon_red_engine", CANDIDATE_VERSION)),
            cwd=root,
        )
        mixed = subprocess.run(
            [
                str(python),
                "-c",
                (
                    "import importlib.metadata as m; "
                    "from red_night_app.composition import evaluate_red_composition_compatibility; "
                    "versions={name:m.version(name) for name in "
                    "('nightrecon-shared-core','nightrecon-red-engine','nightrecon-red-night')}; "
                    "result=evaluate_red_composition_compatibility(versions); "
                    "assert not result.compatible; "
                    "assert result.reason_code == 'red-package-version-mismatch'"
                ),
            ],
            cwd=root,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if mixed.returncode:
            raise AssertionError(
                f"mixed-version fail-closed check failed: {mixed.stdout} {mixed.stderr}"
            )
        assert_workspace_preserved(python, workspace, root)

    print("Red Night packaged deployment lifecycle: passed")


if __name__ == "__main__":
    main()
