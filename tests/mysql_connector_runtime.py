"""Compatibility check for the optional mysql-connector runtime."""

from __future__ import annotations

from importlib.metadata import version

import mysql.connector

from nightrecon.infrastructure_database_mysql import (
    MySqlRuntimeFactory,
    _load_mysql_symbols,
)


def main() -> None:
    installed = version("mysql-connector-python")

    if not installed.startswith("9."):
        raise RuntimeError(
            "Unexpected mysql-connector-python version: "
            f"{installed}"
        )

    if not callable(mysql.connector.connect):
        raise RuntimeError(
            "mysql.connector.connect is unavailable."
        )

    symbols = _load_mysql_symbols()

    if symbols.connect is not mysql.connector.connect:
        raise RuntimeError(
            "NightRecon loaded an unexpected MySQL connect function."
        )

    expected = (
        "MySqlRuntimeFactory("
        "engine='mysql', "
        "tls='identity-verified', "
        "transactions='read-only', "
        "operations='fixed-metadata-only')"
    )

    if repr(MySqlRuntimeFactory(symbols=symbols)) != expected:
        raise RuntimeError(
            "Unexpected MySQL runtime representation."
        )


if __name__ == "__main__":
    main()
