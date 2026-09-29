"""Separate White Night application distribution."""

from __future__ import annotations

from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    from nightrecon_white_engine.white_cli import main as run_white_night

    return run_white_night(argv)
