# Red Night Package Boundary Plan

This plan converts already implemented NightRecon assessment capabilities into
an independently installable Red Night application without copying or rebuilding
the engines.

## Current verified state

The Red application wheel is currently a launcher-only package:

`red-night-app -> nightrecon.red_night -> edition_gateway -> existing NightRecon CLI`

It still depends on `nightrecon==0.31.0`. The current wheel intentionally does
not contain duplicated `nightrecon/` engine files.

The existing Red-owned modules and optional runtime dependencies are defined in
`nightrecon.red_ownership` and documented in `RED_OWNERSHIP.md`.

## Dependency audit result

The proposed Red module set closes over three internal dependency classes:

1. existing Red-owned modules;
2. shared-core compatibility surfaces:
   `authorization_policy`, `edition_catalog`, `edition_policy`, `scope`,
   and `targets`;
3. a small runtime-support layer:
   `__init__`, `cli`, `config`, `edition_gateway`, `logging`,
   `red_night`, and `red_workspace_cli`.

There are no additional unexplained `nightrecon.*` imports in the audited Red
package boundary. `tests/test_red_package_boundary.py` enforces that result.

## Existing Red optional extras

The future standalone package already mirrors the existing runtime versions:

- `browser`: Playwright
- `api`: PyYAML
- `ssh`: Paramiko
- `smb`: Impacket
- `winrm`: pywinrm
- `postgres`: psycopg
- `mysql`: mysql-connector-python
- `all`: union of the above

These are existing capabilities and dependencies, not new feature work.

## Why the monolith dependency still exists

`nightrecon-red-night` cannot yet remove:

`nightrecon==0.31.0`

for these concrete reasons:

1. the Red app wheel remains launcher-only; the Red engine wheel currently
   contains only the first migrated leaf modules while most existing engines
   and the CLI still live in the legacy/root distribution;
2. `red_night_app` imports `nightrecon.red_night`;
3. `red_night` imports `edition_gateway`;
4. the gateway delegates established Red commands to the existing
   `nightrecon.cli`;
5. the legacy CLI eagerly imports the existing Red capability modules;
6. the root distribution currently owns the `nightrecon` package namespace
   and its `__init__.py`;
7. existing tests and third-party compatibility imports use the established
   `nightrecon.*` module paths;
8. uninstall/install behavior must remain safe while the namespace is split;
9. optional Red runtimes are still declared by the root distribution as well as
   the new Red package metadata;
10. the legacy `nightrecon` command must continue working during migration.

## Migration sequence

The physical separation should proceed by **moving**, not copying, coherent
module groups.

### Batch A — package namespace skeleton

Implemented in the v0.32.0 development branch.

The Red engine distribution owns the separate `nightrecon_red_engine`
namespace. Batch A established compatibility/ownership metadata only and proved
install/uninstall coexistence. See `RED_PACKAGE_NAMESPACE.md`.

### Batch B — leaf model/evidence modules

Implemented in the v0.32.0 development branch.

A new `nightrecon-red-engine` distribution breaks the dependency cycle:
legacy/root and Red app depend on the engine; the engine depends only on
shared-core/base libraries. Five existing low-coupling modules are physically
moved without rewriting behavior: `software_identity`,
`service_fingerprint`, `api_models`, `infrastructure_models`, and
`graph_models`. Their established `nightrecon.*` paths remain thin
compatibility re-exports.

### Batch C — discovery/service group

Move the existing discovery, TCP, service/TLS, OS fingerprint, report/session,
storage, and inventory modules as one dependency-coherent group. No algorithms
are rewritten.

### Batch D — web/API/check groups

Move the existing web/browser/DAST, API/GraphQL, and assessment/check modules
with their current tests and optional extras.

### Batch E — infrastructure group

Move existing credentialed infrastructure models/policies/adapters and preserve
the current SSH/SMB/WinRM/database runtime extras and safety behavior.

### Batch F — graph/identity/vulnerability group

Move the existing graph/path, offline identity import, vulnerability, and threat
intelligence modules without changing their evidence semantics.

### Batch G — Red CLI composition

Replace the dependency on the monolithic legacy CLI with a Red-owned CLI
composition layer that invokes the same moved implementations and keeps command
syntax/output compatible.

### Batch H — remove bridge dependency

Only after isolated and combined wheel smoke tests pass across the supported
Python/OS matrix:

1. remove `nightrecon==0.31.0` from `packages/red-night/pyproject.toml`;
2. verify all Red commands in a clean environment;
3. verify shared-core authorization remains mandatory;
4. verify legacy compatibility imports where promised;
5. verify uninstalling Red leaves other Night/shared packages intact.

## Stop rule

If a migration batch starts implementing scanner, crawler, API, infrastructure,
vulnerability, check, graph, or reporting behavior that already exists, stop.
The task is package separation and import migration, not feature recreation.

Genuinely new Red capability work resumes only after the package boundary is
stable, focused on the open acceptance gaps such as live AD/Entra collection and
controlled validation/emulation.
