"""Allow `python -m white_night_app` as an installed entry point."""

from __future__ import annotations

import sys

from . import main


if __name__ == "__main__":
    sys.exit(main())
