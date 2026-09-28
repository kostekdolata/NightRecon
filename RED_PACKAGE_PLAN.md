# Red Night Package Boundary Plan

This plan converts already implemented NightRecon assessment capabilities into
an independently installable Red Night application without copying or rebuilding
the engines.

## Current verified state

Red Night now has an independently installable application and engine boundary:

`red-night-app -> nightrecon_red_engine.red_cli -> canonical Red engine modules`

The Red application no longer declares or requires `nightrecon==0.31.0`.
The legacy root distribution remains available for compatibility, but it is not
part of the Red app runtime dependency chain.

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

## Legacy compatibility status

The monolithic `nightrecon` distribution remains installable so existing
imports and the legacy console script continue to work. It depends on the Red
engine for migrated implementations, but the standalone Red app does not depend
on the monolith. Compatibility aliases remain intentionally in place during the
v0.32.0 transition.

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

Batch C is being executed in dependency-closed stages rather than forcing a
Red-engine-to-legacy dependency.

Batch C1 physically migrates `host_discovery`, `ports`, `tcp_scanner`,
`tls_detection`, `service_probe`, `resolver`, `session`, and
`discovery_report`. The network-capable legacy paths are true module aliases
to preserve established patch points and object identity.

Batch C2 follows Batch D and migrates `service_detection` and `os_fingerprint`,
whose former web dependency is now canonical in the Red engine.

Batch C3 follows Batches E and F1 and migrates `report`, `storage`,
`asset_inventory`, and `asset_inventory_store`. All of their former
infrastructure/vulnerability/report-type dependencies are now canonical in the
Red engine, completing the discovery/service/reporting/inventory group. They move only when the
required dependency group is canonical in the Red engine. No algorithms are
rewritten.

### Batch D — web/API/check groups

Implemented in the v0.32.0 development branch.

The complete existing web/browser/DAST, API/GraphQL, and assessment/check groups
now live canonically in `nightrecon_red_engine`. Internal imports point only to
the Red-engine namespace or already-separated shared dependencies, while legacy
`nightrecon.*` paths remain module aliases for compatibility and monkeypatch
identity. The Red-engine distribution now also declares the existing browser and
API optional extras. No assessment algorithms were rewritten.

### Batch E — infrastructure group

Implemented in the v0.32.0 development branch.

All existing credentialed infrastructure providers, policies, execution models,
database adapters, network-device logic, reporting, SSH, SMB, and WinRM modules
now live canonically in `nightrecon_red_engine`. Shared scope/target policy
imports resolve directly through shared core. The existing SSH/SMB/WinRM,
PostgreSQL, and MySQL runtimes remain optional Red-engine extras. No execution
semantics or safety policy were rewritten.

### Batch F — graph/identity/vulnerability group

Implemented in the v0.32.0 development branch.

The vulnerability/threat-intelligence and graph/identity groups now live
canonically in `nightrecon_red_engine`, including the offline Red directory
import/CLI. Their legacy paths are compatibility aliases. Evidence semantics
and existing safety behavior are unchanged.

### Batch G — Red CLI composition

Implemented and verified in the v0.32.0 development branch.

`nightrecon_red_engine.red_cli` is composed from the existing CLI behavior with
imports redirected to canonical Red-engine modules and shared-core policy.
`identity` and `workspace` route directly to Red-owned implementations.
Both the separate Red app entrypoint and the legacy `red-night` compatibility
launcher now call this Red-owned CLI instead of `nightrecon.cli`. The
distribution smoke verifies the Red app can run with no legacy `nightrecon`
package installed before the metadata bridge is removed in Batch H.

### Batch H — remove bridge dependency

Implemented in the v0.32.0 development branch.

The Red app no longer declares `nightrecon==0.31.0`. Isolated and combined
distribution smoke tests verify direct Red-engine execution, shared-core
authorization, compatibility imports in combined installs, and safe app
uninstallation without removing the legacy/root or Red engine packages.

## Stop rule

If a migration batch starts implementing scanner, crawler, API, infrastructure,
vulnerability, check, graph, or reporting behavior that already exists, stop.
The task is package separation and import migration, not feature recreation.

Genuinely new Red capability work resumes only after the package boundary is
stable, focused on the open acceptance gaps such as live AD/Entra collection and
controlled validation/emulation.
