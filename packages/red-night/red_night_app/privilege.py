"""Platform privilege contract for active Red Night execution."""

from __future__ import annotations

import ctypes
import os


PRIVILEGE_POLICY = "required-platform-privileged"


def is_platform_privileged() -> bool:
    """Return whether the current process has the platform's required privilege."""

    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False

    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    return geteuid() == 0


def require_platform_privilege() -> None:
    """Fail closed when an active Red Night process is not privileged."""

    if not is_platform_privileged():
        raise PermissionError(
            "Red Night requires privileged OS execution in standalone, "
            "composed/full-stack, and Live deployments"
        )
