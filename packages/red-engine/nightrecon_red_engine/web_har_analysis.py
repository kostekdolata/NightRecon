"""Offline HTTP Archive comparison for authorised assessment evidence.

Never replays requests or stores cookies, query strings, bodies or headers.
"""
from __future__ import annotations
from dataclasses import dataclass
from .web_har_import import HarEvidence

@dataclass(frozen=True)
class WebResponseChange:
    origin: str
    method: str
    previous_statuses: tuple[int, ...]
    current_statuses: tuple[int, ...]

def compare_har(before: HarEvidence, after: HarEvidence, allowed_origins: frozenset[str]) -> tuple[WebResponseChange, ...]:
    def grouped(report: HarEvidence):
        results: dict[tuple[str,str],set[int]]={}
        for request in report.requests:
            if request.origin not in allowed_origins:
                continue
            results.setdefault((request.origin,request.method),set()).add(request.status)
        return {key:tuple(sorted(value)) for key,value in results.items()}
    old,new=grouped(before),grouped(after)
    return tuple(WebResponseChange(key[0],key[1],old.get(key,()),new.get(key,()))
        for key in sorted(old.keys()|new.keys()) if old.get(key)!=new.get(key))
