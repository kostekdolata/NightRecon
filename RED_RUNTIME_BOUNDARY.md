# Red Night Runtime Boundary

This document records the current v0.32.0 development-preview boundary after
shared-core extraction and workspace composition work.

## Current package boundary

`packages/red-night/` is a separately installable Red Night application
distribution, but Red's assessment engines are not yet isolated from the legacy
runtime.

The application currently depends on:

- `nightrecon==0.31.0` for the legacy Red CLI/runtime bridge still being migrated;
- `nightrecon-red-engine==0.32.0.dev0` for physically separated Red engine modules;
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

## Red-owned existing capability assignment

Existing NightRecon assessment engines remain canonical in their proven modules.
Red ownership is recorded in [RED_OWNERSHIP.md](RED_OWNERSHIP.md) and
`nightrecon.red_ownership` rather than by copying implementations.

`nightrecon.red_host_discovery`, `red_tcp_scanner`, and
`red_service_detection` are thin ownership facades over the original modules.
They contain no duplicate network implementation. The Red/legacy CLI may import
through those facades while the original modules and established test patch
points remain stable.

This is an ownership and packaging seam, not a feature rewrite. Physical module
moves should happen only when a coherent Red engine package can be built without
duplicating code or changing behavior.

## Existing Red engines awaiting package separation

Discovery/scanning, service/TLS/OS evidence, web/DAST, API, credentialed
infrastructure assessment, vulnerability/check execution, asset inventory,
reporting, and graph/path foundations already exist and are assigned to Red.

Package separation is now active through the independent
`nightrecon-red-engine` distribution. The first migrated leaf modules are
`software_identity`, `service_fingerprint`, `api_models`,
`infrastructure_models`, and `graph_models`; their legacy paths are
compatibility re-exports. The remaining boundary problem is removing the
monolithic `nightrecon==0.31.0` CLI/runtime bridge after the remaining coherent
engine groups move. The ordered work is tracked in
[RED_PACKAGE_PLAN.md](RED_PACKAGE_PLAN.md).

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
