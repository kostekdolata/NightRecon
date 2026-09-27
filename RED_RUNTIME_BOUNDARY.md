# Red Night Runtime Boundary Baseline

This document records the current Red Night runtime coupling before shared-core extraction begins.

## Current package boundary

`packages/red-night/` is a separate Red Night application distribution, but it is not yet an isolated Red runtime.

The application package currently depends on:

- `nightrecon==0.31.0` — the full legacy NightRecon runtime.

The launcher path is:

`red-night-app -> red_night_app.main -> nightrecon.red_night.main -> nightrecon.edition_gateway.run_edition_cli`

The gateway fail-closes commands that are not explicitly assigned to Red Night, but approved Red commands other than the dedicated offline identity import still execute through the legacy `nightrecon.cli` adapter.

## Boundary map

### Mandatory shared-core candidates

These modules contain cross-edition policy or safety primitives and should move behind a separately installable shared-core boundary before Red engine isolation is considered complete:

- `edition_catalog.py` — edition identity and product metadata.
- `edition_gateway.py` policy portion — fail-closed edition command ownership.
- `scope.py` — explicit authorization scope evaluation.
- `targets.py` — normalized target parsing used by scope.
- configuration/audit/approval primitives that are proven to be required by more than one Night as extraction proceeds.

The shared core must not contain scanners, protocol clients, browser automation, credentialed infrastructure adapters, vulnerability checks, or Red-only graph/import logic.

### Red-owned engine candidates

These capabilities belong to Red Night when they are split out of the legacy runtime:

- network discovery, TCP scanning, service/version and OS evidence
- web/API assessment and bounded browser workflows
- infrastructure assessment adapters
- vulnerability/check execution used for authorized Red assessment
- identity evidence import, graph construction, path review, and future authorized identity collectors
- Red reporting and controlled validation surfaces

Representative current modules include `host_discovery.py`, `tcp_scanner.py`, `service_detection.py`, `web_*.py`, `api_*.py`, `infrastructure_*.py`, `red_directory_*.py`, and `graph_*.py`.

### Legacy / not part of the first extraction

- `cli.py` remains the compatibility CLI during migration.
- future Blue, White, Purple, and Black application code is not to be pulled into Red.
- specialist-tool parity work, live collectors, and controlled validation are separate later gates.

## Extraction rule

Each isolation batch must:

1. preserve the existing `nightrecon` CLI;
2. preserve fail-closed Red command routing;
3. keep authorization/scope checks authoritative;
4. avoid moving network-capable code into the shared core;
5. add or update package-install smoke coverage;
6. keep isolated and combined installations deterministic;
7. leave master at a fully tested checkpoint before the next batch.

## First physical extraction target

The first code extraction should move edition identity plus fail-closed command-ownership policy into a small dependency with no network-capable imports. The legacy gateway and the Red application should then consume that same policy. Execution may still adapt into the legacy CLI temporarily, but policy ownership must no longer require importing the legacy CLI.

After that seam is verified, scope/target authorization primitives can be extracted, followed by Red-owned execution modules.
