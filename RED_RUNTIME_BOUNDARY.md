# Red Night Runtime Boundary

This document records the current v0.32.0 development-preview boundary after
shared-core extraction and workspace composition work.

## Current package boundary

`packages/red-night/` is a separately installable Red Night application
distribution, but Red's assessment engines are not yet isolated from the legacy
runtime.

The application currently depends on:

- `nightrecon==0.31.0` for the legacy Red execution engines still being migrated;
- `nightrecon-shared-core==0.32.0.dev0` for canonical cross-Night policy,
  authorization primitives, evidence contracts, engagement storage, and
  workspace coordination.

The launcher path remains:

`red-night-app -> red_night_app.main -> nightrecon.red_night.main -> nightrecon.edition_gateway.run_edition_cli`

The gateway fail-closes commands that are not explicitly assigned to Red Night.
The dedicated `identity` and `workspace` commands route to Red-specific
adapters; other approved Red commands still use the legacy CLI until their
engines are physically extracted.

## Shared core now owns

The independently installable, network-free shared core is canonical for:

- Night identity and fail-closed command ownership policy;
- target parsing and explicit scope authorization;
- versioned, secret-free evidence records and engagement envelopes;
- engagement coordination metadata;
- backend-neutral engagement-store semantics;
- deterministic local file storage for standalone applications;
- shared workspace summaries, evidence breakdowns, conflict-safe merges, and
  portable import/export.

The legacy `nightrecon.edition_policy`, `authorization_policy`, `scope`,
and `targets` surfaces are compatibility re-exports. Shared core must not
import the legacy application runtime or any Night application.

Workspace evidence and metadata are coordination context only. An
`authorization_reference` is a reference to separately enforced authorization;
it is never an approval flag and never grants permission for an active action.

## Workspace composition boundary

`LocalWorkspace` uses one canonical `engagements.json` store under a workspace
root. Multiple independently installed Nights can use the same contracts and
workspace abstraction without importing each other.

The current file-backed workspace is intended for standalone use and serialized
local writers. It does not claim safe concurrent multi-process writes. A future
composed desktop/service/database backend must implement the same workspace/store
semantics while providing appropriate locking or transactions.

Red Night exposes the first workspace adapter:

- `red-night workspace list <root>`
- `red-night workspace show <root> --engagement-id <id>`
- `red-night workspace import <root> <envelope.json>`
- `red-night workspace export <root> --engagement-id <id> --output <path>`

These commands read, summarize, import, or export evidence only. They do not
scan, collect, approve, or authorize targets.

## Red-owned execution extraction

Bounded host discovery and TCP connect scanning now have canonical Red-owned
modules:

- `nightrecon.red_host_discovery`
- `nightrecon.red_tcp_scanner`
- `nightrecon.red_service_detection`

The legacy `nightrecon.host_discovery` and `nightrecon.tcp_scanner` modules
are compatibility re-exports only, and the compatibility CLI consumes the
canonical Red modules directly. This establishes ownership without changing the
public API or bypassing existing CLI scope checks.

These engines are still physically inside the legacy `nightrecon` distribution,
so this is an ownership/runtime seam rather than complete package isolation.
Moving them into a separately versioned Red engine package remains a later
packaging gate.

## Red-owned engines still to extract

The remaining Red runtime boundary includes:

- service/version and OS evidence beyond the extracted TCP primitives;
- web/API assessment and bounded browser workflows;
- infrastructure assessment adapters;
- vulnerability/check execution for authorized Red assessment;
- identity graph construction/path review and future authorized collectors;
- Red reporting and controlled validation surfaces.

Representative legacy modules include `host_discovery.py`, `tcp_scanner.py`,
`service_detection.py`, `web_*.py`, `api_*.py`,
`infrastructure_*.py`, `red_directory_*.py`, and `graph_*.py`.

## Extraction rules

Each isolation batch must:

1. preserve the existing `nightrecon` CLI;
2. preserve fail-closed Red command ownership;
3. keep shared authorization/scope checks authoritative;
4. keep network-capable and Night-specific execution out of shared core;
5. preserve standalone and combined package-install smoke coverage;
6. maintain deterministic, versioned evidence/workspace contracts;
7. avoid Night-to-Night runtime imports;
8. keep imported/shared evidence non-authoritative for active operations.

## Next physical extraction target

The next package-boundary work should continue from the extracted discovery/TCP/service
seam into evidence projection and the remaining service helper modules, keeping existing
scope checks and compatibility behavior intact. Once a coherent Red execution
slice no longer depends on unrelated legacy modules, it can move into a
separately versioned Red engine distribution.
