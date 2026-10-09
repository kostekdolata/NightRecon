"""Read-only import of a bounded Metasploit module catalogue JSON export.

No RPC connection, payload handling, module execution, network access, or subprocess.
All imported descriptions remain third-party metadata, not validated findings.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

MAX_JSON_BYTES = 4 * 1024 * 1024
MAX_MODULES = 5000
MODULE_TYPES = frozenset({"auxiliary", "exploit", "post", "encoder", "payload", "nop", "evasion"})


@dataclass(frozen=True)
class ModuleSummary:
    fullname: str
    module_type: str
    name: str
    description: str
    references: tuple[str, ...]


@dataclass(frozen=True)
class MetasploitCatalogue:
    source: str
    modules: tuple[ModuleSummary, ...]


def parse_module_catalogue(data: bytes) -> MetasploitCatalogue:
    """Parse a deliberately small, documented interchange format.

    Input: {"modules": [{"fullname": "auxiliary/scanner/example",
      "name": "...", "description": "...", "references": ["CVE-..."]}]}
    This is a Red Night interchange schema, not an assertion that msfconsole
    directly exports this exact format.
    """
    if len(data) > MAX_JSON_BYTES:
        raise ValueError("Metasploit catalogue exceeds size limit.")
    try:
        obj = json.loads(data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Invalid module catalogue JSON.") from exc
    if not isinstance(obj, dict) or not isinstance(obj.get("modules"), list):
        raise ValueError("Expected a modules array.")
    raw_modules = obj["modules"]
    if len(raw_modules) > MAX_MODULES:
        raise ValueError("Too many modules.")
    modules = []
    for entry in raw_modules:
        if not isinstance(entry, dict):
            raise ValueError("Each module must be an object.")
        fullname = entry.get("fullname")
        if not isinstance(fullname, str) or len(fullname) > 256 or "/" not in fullname:
            raise ValueError("Invalid module fullname.")
        kind = fullname.split("/", 1)[0]
        if kind not in MODULE_TYPES or any(part in ("", ".", "..") for part in fullname.split("/")):
            raise ValueError("Invalid module path or type.")
        name = entry.get("name", "")
        description = entry.get("description", "")
        references = entry.get("references", [])
        if not isinstance(name, str) or not isinstance(description, str):
            raise ValueError("Invalid module name or description.")
        if not isinstance(references, list) or len(references) > 64 or not all(isinstance(x, str) for x in references):
            raise ValueError("Invalid module references.")
        modules.append(ModuleSummary(
            fullname=fullname,
            module_type=kind,
            name=name[:256],
            description=description[:2048],
            references=tuple(x[:256] for x in references),
        ))
    return MetasploitCatalogue(source="metasploit-catalogue-unverified", modules=tuple(modules))


def import_module_catalogue_file(path: str | Path) -> MetasploitCatalogue:
    with Path(path).open("rb") as handle:
        return parse_module_catalogue(handle.read(MAX_JSON_BYTES + 1))
