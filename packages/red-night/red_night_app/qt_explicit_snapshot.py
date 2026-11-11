"""Explicit, read-only engagement loading for the Qt desktop.

No workspace discovery, authorization mutation, scanning or subprocess launch.
The operator must supply all three existing evidence paths and an engagement ID.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from .operations_read_model import OperationsSnapshot, read_operations_snapshot


def load_explicit_snapshot(argv: list[str]) -> OperationsSnapshot | None:
    parser = argparse.ArgumentParser(description="Red Night read-only Qt overview")
    parser.add_argument("--engagement-id")
    parser.add_argument("--authority-db")
    parser.add_argument("--audit-path")
    parser.add_argument("--review-db")
    args = parser.parse_args(argv)
    values = (args.engagement_id, args.authority_db, args.audit_path, args.review_db)
    if not any(value is not None for value in values):
        return None
    if not all(values):
        parser.error("all four read-only engagement arguments are required together")
    if len(args.engagement_id) > 128:
        parser.error("engagement identifier exceeds 128 characters")
    paths = (Path(args.authority_db), Path(args.audit_path), Path(args.review_db))
    if not all(path.is_file() for path in paths):
        parser.error("all three evidence files must already exist")
    # Reuse the existing bounded, immutable-read-only operations model.
    return read_operations_snapshot(
        engagement_id=args.engagement_id,
        authority_db=paths[0], audit_path=paths[1], review_db=paths[2],
    )
