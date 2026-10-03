"""Windows installer launcher for Red Night."""

from __future__ import annotations

import importlib.metadata as metadata
import json
import os
from pathlib import Path
import subprocess
import sys

from .composition import evaluate_red_composition_compatibility


RED_DISTRIBUTIONS = (
    "nightrecon-shared-core",
    "nightrecon-red-engine",
    "nightrecon-red-night",
)
BUILD_INFO_FILENAME = "build-info.json"


def _is_windows_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def _application_path() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def _build_info() -> dict[str, object]:
    path = _application_path() / BUILD_INFO_FILENAME
    if not path.is_file():
        return {"available": False}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"available": False, "valid": False}
    if not isinstance(payload, dict):
        return {"available": False, "valid": False}
    payload = dict(payload)
    payload["available"] = True
    payload["valid"] = True
    return payload


def deployment_info() -> dict[str, object]:
    versions = {name: metadata.version(name) for name in RED_DISTRIBUTIONS}
    compatibility = evaluate_red_composition_compatibility(versions)
    return {
        "product": "Red Night",
        "platform": "windows",
        "operational": False,
        "authorization_effect": "none",
        "package_versions": versions,
        "package_compatible": compatibility.compatible,
        "compatibility_reason": compatibility.reason_code,
        "build": _build_info(),
    }


def _request_elevation() -> int:
    if os.name != "nt":
        raise RuntimeError("Red Night Windows launcher requires Windows")
    import ctypes
    executable = str(Path(sys.executable).resolve())
    parameters = subprocess.list2cmdline(sys.argv[1:])
    result = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", executable, parameters, str(Path.cwd()), 1
    )
    if result <= 32:
        raise PermissionError(
            "Red Night elevation was not granted; privileged execution is required"
        )
    return 0


def main() -> None:
    if sys.argv[1:] == ["--deployment-info"]:
        print(json.dumps(deployment_info(), sort_keys=True))
        return
    if sys.argv[1:] == ["--deployment-self-test"]:
        from .windows_deployment_self_test import run_windows_deployment_self_test
        print(json.dumps(run_windows_deployment_self_test(), sort_keys=True))
        return
    if os.name != "nt":
        raise RuntimeError("red_night_app.windows_launcher is Windows-only")
    if not _is_windows_admin():
        raise SystemExit(_request_elevation())
    from . import main as run_red_night
    run_red_night()


if __name__ == "__main__":
    main()
