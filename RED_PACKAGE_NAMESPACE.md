# Red Night Package Namespace Contract

Batch A establishes the package namespace used for Red Night separation without
moving or copying any assessment engine.

## Namespace

The Red distribution owns:

`nightrecon_red_engine`

The existing root runtime continues to own:

`nightrecon`

during the migration bridge.

The Red namespace is deliberately separate so installing or uninstalling the Red
distribution cannot overwrite or delete files owned by the legacy root
distribution.

## Current contents

The namespace contains packaging and compatibility metadata only:

- namespace identity;
- the legacy namespace name;
- a guarded resolver for modules already declared Red-owned.

It contains no scanner, crawler, browser, API, infrastructure, vulnerability,
check, graph, identity, or reporting implementation.

The guarded resolver accepts only module names declared by the canonical
`nightrecon.red_ownership` manifest and then imports the existing proven module
from its established `nightrecon.<module>` path.

This is a temporary migration bridge, not a second implementation.

## Compatibility rules

Until physical engine migration starts:

1. existing `nightrecon.*` module paths remain canonical;
2. existing unit-test patch points remain unchanged;
3. `nightrecon_red_engine` must never contain copied engine algorithms;
4. the Red package may resolve only modules explicitly assigned to Red;
5. shared-core compatibility modules are not exposed as Red engines;
6. installing Red must not overwrite the legacy `nightrecon` package;
7. uninstalling Red must remove `nightrecon_red_engine` and
   `red-night-app` while leaving the legacy package and command intact;
8. shared-core remains a mandatory dependency.

## Verification

The contract is enforced by:

- `tests/test_red_package_namespace.py`;
- `tests/test_red_package_boundary.py`;
- `tests/red_night_distribution_smoke.py`.

The wheel smoke requires the Red wheel to contain both `red_night_app/` and
`nightrecon_red_engine/`, while containing no `nightrecon/` engine files.

## Next migration boundary

Batch B may physically move only low-coupling existing Red modules after their
dependency group is verified. It must move code rather than copy it, preserve
the old import path through compatibility re-exports where required, and leave
behavior unchanged.
