# Red Night Package Namespace Contract

The Red engine distribution owns the separate `nightrecon_red_engine`
namespace. The legacy compatibility distribution continues to own
`nightrecon` while migration is in progress.

## Distribution ownership

- `nightrecon-red-engine` owns `nightrecon_red_engine`.
- `nightrecon` depends on the Red engine package during compatibility migration.
- `nightrecon-red-night` depends on both the Red engine and the legacy root
  package until its CLI bridge is removed.
- `nightrecon-red-engine` never depends on `nightrecon`, preventing a cycle.

## Compatibility rules

1. A module that physically migrates has one canonical implementation under
   `nightrecon_red_engine.<module>`.
2. Its established `nightrecon.<module>` path becomes a thin re-export only.
3. Existing object identity is preserved through the compatibility path.
4. A migrated module is never copied into both distributions.
5. Engine migration must not change algorithms, outputs, safety policy, or
   public data models.
6. Shared-core remains below the Red engine boundary.
7. Red app uninstall must not remove the separately installed Red engine or the
   legacy compatibility package.
8. The engine package must contain no `nightrecon/` files.

## Batch A

Batch A established the namespace and coexistence contract without moving
assessment implementations.

## Batch B

Batch B establishes a separately installable `nightrecon-red-engine`
distribution and physically migrates the first five low-coupling, network-free
modules:

- `software_identity`
- `service_fingerprint`
- `api_models`
- `infrastructure_models`
- `graph_models`

The old module files become compatibility re-exports. Their existing behavior is
unchanged.

## Verification

The contract is enforced by:

- `tests/test_red_package_namespace.py`;
- `tests/test_red_engine_leaf_migration.py`;
- `tests/test_red_package_boundary.py`;
- `tests/red_night_distribution_smoke.py`.

The distribution smoke builds four wheels: shared core, Red engine, legacy/root
compatibility, and Red app. It checks namespace ownership, canonical-object
identity, and install/uninstall coexistence.
