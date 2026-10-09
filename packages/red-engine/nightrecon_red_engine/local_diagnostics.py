"""Explicit local-only diagnostic command presets for governed lab smoke tests.

Never accepts user-provided executables or arguments. These presets do not
perform network probing, credential access or exploit validation.
"""
from __future__ import annotations
from pathlib import Path
import sys
from .governed_command_runner import FixedCommand

def local_python_version() -> FixedCommand:
    """Safe local command used to validate end-to-end governed execution."""
    return FixedCommand(
        name="local-python-version",
        executable=Path(sys.executable).resolve(),
        arguments=("--version",),
        capability="external.local.diagnostics",
        impact="low",
        timeout_seconds=5,
        elevated=False,
    )

def get_local_diagnostic(name: str) -> FixedCommand:
    if name != "local-python-version":
        raise PermissionError("Unregistered local diagnostic")
    return local_python_version()
