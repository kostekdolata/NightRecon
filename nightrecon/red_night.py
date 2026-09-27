"""Red Night launcher: allow only Red-owned commands through the shared gateway."""

from __future__ import annotations

import sys
from collections.abc import Sequence

from nightrecon.edition_gateway import EditionRouteError, run_edition_cli


def main(argv: Sequence[str] | None = None) -> None:
    """Run Red Night without weakening existing authorization checks."""

    arguments = sys.argv[1:] if argv is None else argv
    try:
        run_edition_cli("red", arguments)
    except EditionRouteError as exc:
        print(f"red-night: {exc}", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    main()
