# Red Night Existing Capability Ownership

This document is the source of truth for assigning already implemented
NightRecon capability code to Red Night. Assignment does not mean rewriting or
copying a working module. Existing implementation modules remain canonical until
a later packaging move can relocate them without changing behavior.

## Rule

For an already implemented capability:

1. keep the proven implementation and tests;
2. assign ownership through this manifest, Red command routing, and package metadata;
3. use a thin facade only when a Red-specific import surface is useful;
4. do not duplicate the implementation merely to add a `red_` prefix;
5. physically move modules only as a coherent package-boundary change with all
   imports/tests updated in one verified batch.

Shared-core modules must remain network-free and Night-neutral.

## Existing Red capability groups

### Discovery, scan, service and inventory

`host_discovery`, `tcp_scanner`, `service_detection`,
`service_probe`, `service_fingerprint`, `software_identity`,
`tls_detection`, `os_fingerprint`, `resolver`, `ports`,
`discovery_report`, `report`, `storage`, `session`,
`asset_inventory`, and `asset_inventory_store`.

### Web and safe-active application assessment

All existing `web_*`, `browser_*`, and `dast_*` modules plus
`security_headers`.

### API assessment

All existing `api_*` modules plus `graphql_report`.

### Credentialed infrastructure assessment

All existing `infrastructure_*` modules plus `credential_providers` and
`credential_resolution`.

### Vulnerability and threat intelligence

`cpe_identity`, `nvd_provider`, `cisa_kev_provider`,
`epss_provider`, `vulnerability_intelligence`, and `threat_context`.

### Assessment/check framework

`assessment_engine`, `builtin_checks`, and all existing `check_*` modules.

### Graph, identity evidence and path review

All existing `graph_*` modules plus the Red offline directory import/CLI.

These are already implemented NightRecon capabilities. Their next Red work is
packaging, ownership, integration evidence, and acceptance benchmarking—not
feature reimplementation.

## Red optional runtime extras

The existing optional dependencies are Red runtime extras:

- browser: Playwright
- API schema YAML: PyYAML
- SSH: Paramiko
- SMB: Impacket
- WinRM: pywinrm
- PostgreSQL: psycopg
- MySQL: mysql-connector-python

## Shared/core responsibility

Authorization/scope, target parsing, edition policy, cross-Night evidence
contracts, engagement/workspace contracts, and safety primitives needed by every
Night belong below the Red application boundary.

Current compatibility modules such as `authorization_policy`, `scope`,
`targets`, `edition_catalog`, and `edition_policy` re-export canonical
shared-core behavior and are not Red engine modules.

## Thin Red ownership facades

`red_host_discovery`, `red_tcp_scanner`, and `red_service_detection`
are ownership/import facades only. They re-export the original proven
implementations and contain no network implementation themselves.

## Genuine remaining Red product work

The major remaining capability gaps are not duplicate reconnaissance features.
They include:

- authorization-first live AD/Entra collection;
- privilege/trust relationship collection and validation;
- controlled approval-gated validation/exploitability workers;
- ATT&CK-mapped controlled emulation;
- revocation/stop/cleanup controls for higher-impact validation;
- multi-operator engagement/review workflows;
- professional acceptance/comparison labs for coverage, false positives,
  performance and evidence quality;
- independent Red packaging that no longer depends on the monolithic
  `nightrecon==0.31.0` distribution.

Before any future Red feature batch, check this document and
`nightrecon.red_ownership` to avoid rebuilding existing functionality.


## Packaging audit

The current dependency audit is implemented in
`nightrecon.red_package_boundary`. It parses imports from the existing source
modules and classifies them as Red-owned, shared-core compatibility, runtime
support, or unresolved. The release boundary test requires the unresolved set
to remain empty.

The exact bridge-removal sequence is maintained in `RED_PACKAGE_PLAN.md`.


## Physically migrated to the Red engine distribution

The canonical implementation for the following existing modules now lives under
`nightrecon_red_engine`:

- `software_identity`
- `service_fingerprint`
- `api_models`
- `infrastructure_models`
- `graph_models`
- `host_discovery`
- `ports`
- `tcp_scanner`
- `tls_detection`
- `service_probe`
- `resolver`
- `session`
- `discovery_report`

The Batch C1 discovery/runtime modules plus all web/browser/DAST, API/GraphQL,
and assessment/check modules are now canonical in the Red engine. The remaining
discovery modules are the dependency-blocked portion of the larger discovery group. Modules that currently depend on web, check,
vulnerability, API, or infrastructure report surfaces remain in the legacy
package until those dependencies migrate.

Their old `nightrecon.*` files are compatibility re-exports or module aliases only. The migrated
set is canonically published by `nightrecon_red_engine.MIGRATED_MODULES` and
consumed by `nightrecon.red_ownership`.
