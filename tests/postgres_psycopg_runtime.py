"""Compatibility check for the optional psycopg PostgreSQL runtime."""

from __future__ import annotations

from importlib.metadata import version
import inspect

import psycopg

from nightrecon.infrastructure_database_psycopg import (
    PsycopgRuntimeFactory,
    _load_psycopg_symbols,
)


def main() -> None:
    installed = version("psycopg")

    if not installed.startswith("3."):
        raise RuntimeError(
            "Unexpected psycopg version: "
            f"{installed}"
        )

    signature = inspect.signature(psycopg.connect)

    for name in ("conninfo", "autocommit"):
        if name not in signature.parameters:
            raise RuntimeError(
                "psycopg.connect is missing "
                f"{name}."
            )

    symbols = _load_psycopg_symbols()

    if symbols.connect is not psycopg.connect:
        raise RuntimeError(
            "NightRecon loaded an unexpected psycopg connect function."
        )

    expected = (
        "PsycopgRuntimeFactory("
        "engine='postgresql', "
        "tls='verify-full', "
        "transactions='read-only', "
        "operations='fixed-metadata-only')"
    )

    if repr(PsycopgRuntimeFactory(symbols=symbols)) != expected:
        raise RuntimeError(
            "Unexpected PostgreSQL runtime representation."
        )


if __name__ == "__main__":
    main()
