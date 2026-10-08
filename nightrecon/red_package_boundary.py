"""Development-time dependency audit for the future Red Night engine package.

The audit reads the existing proven Python sources and classifies internal
NightRecon imports. It does not copy, rewrite, or execute assessment engines.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from nightrecon.red_ownership import (
    RED_ENGINE_FACADES,
    RED_ENGINE_INTERNAL_SUPPORT_MODULES,
    RED_MIGRATED_ENGINE_MODULES,
    RED_RUNTIME_SUPPORT_MODULES,
    SHARED_CORE_COMPATIBILITY_MODULES,
    red_modules,
    red_package_modules,
)


@dataclass(frozen=True)
class RedDependencyAudit:
    owned_edges: tuple[tuple[str, str], ...]
    shared_edges: tuple[tuple[str, str], ...]
    support_edges: tuple[tuple[str, str], ...]
    unresolved_edges: tuple[tuple[str, str], ...]


def _internal_imports(path: Path) -> tuple[str, ...]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: set[str] = set()
    for node in ast.walk(tree):
        candidates: list[str] = []
        if isinstance(node, ast.Import):
            candidates.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            candidates.append(node.module)

        for name in candidates:
            for prefix in ("nightrecon.", "nightrecon_red_engine."):
                if name.startswith(prefix):
                    imports.add(name.split(".", 1)[1].split(".", 1)[0])
                    break
    return tuple(sorted(imports))


def audit_red_dependencies(
    legacy_root: str | Path,
    engine_root: str | Path,
) -> RedDependencyAudit:
    legacy = Path(legacy_root)
    engine = Path(engine_root)
    owned = set(red_modules())
    migrated = set(RED_MIGRATED_ENGINE_MODULES)
    shared = set(SHARED_CORE_COMPATIBILITY_MODULES)
    support = (
        set(RED_RUNTIME_SUPPORT_MODULES)
        | set(RED_ENGINE_FACADES)
        | set(RED_ENGINE_INTERNAL_SUPPORT_MODULES)
    )
    package = set(red_package_modules())

    owned_edges: list[tuple[str, str]] = []
    shared_edges: list[tuple[str, str]] = []
    support_edges: list[tuple[str, str]] = []
    unresolved_edges: list[tuple[str, str]] = []

    for module in sorted(package):
        source = (
            engine / f"{module}.py"
            if module in migrated
            else legacy / f"{module}.py"
        )
        if not source.is_file():
            unresolved_edges.append((module, "<missing-module>"))
            continue

        for dependency in _internal_imports(source):
            edge = (module, dependency)
            if dependency in owned:
                owned_edges.append(edge)
            elif dependency in shared:
                shared_edges.append(edge)
            elif dependency in support:
                support_edges.append(edge)
            else:
                unresolved_edges.append(edge)

    return RedDependencyAudit(
        owned_edges=tuple(sorted(set(owned_edges))),
        shared_edges=tuple(sorted(set(shared_edges))),
        support_edges=tuple(sorted(set(support_edges))),
        unresolved_edges=tuple(sorted(set(unresolved_edges))),
    )
