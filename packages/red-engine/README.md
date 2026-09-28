# NightRecon Red Engine

This development-preview distribution owns the `nightrecon_red_engine`
namespace used to physically separate existing Red Night capabilities from the
legacy monolithic `nightrecon` package.

It does not recreate assessment functionality. Modules are moved here from their
existing proven implementations, and the old `nightrecon.<module>` paths remain
thin compatibility re-exports during migration.

Batch B initially migrates five low-coupling, network-free modules:

- `software_identity`
- `service_fingerprint`
- `api_models`
- `infrastructure_models`
- `graph_models`

The package depends only on shared-core/base libraries, never on the legacy
`nightrecon` distribution. This prevents a circular dependency while allowing
both the legacy compatibility package and the Red Night application to consume
the same canonical Red engine implementation.

Batch C1 adds the dependency-closed discovery/runtime core without changing its
algorithms:

- `host_discovery`
- `ports`
- `tcp_scanner`
- `tls_detection`
- `service_probe`
- `resolver`
- `session`
- `discovery_report`

Network-capable legacy module paths are module aliases to the canonical Red
engine modules so established monkeypatch/test seams continue to target the
actual implementation.
