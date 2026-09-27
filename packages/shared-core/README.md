# NightRecon Shared Core

Development-preview package for capabilities that must remain common across independently installable NightRecon applications.

Current exported surface:

- edition identity and fail-closed command ownership policy
- explicit target parsing and scope authorization
- versioned, secret-free cross-Night evidence contracts
- backend-neutral engagement-store protocol
- in-memory reference store
- portable deterministic JSON file store for standalone Nights

The dependency direction is always:

`Night application -> nightrecon-shared-core`

The shared core must never depend on Red, Blue, White, Purple, Black, or the legacy application runtime. It is intentionally network-free and contains no scanners, protocol clients, browser automation, credential providers, exploit/validation engines, or Night-specific graph logic.

Standalone Nights can use `FileEngagementStore` for local persisted engagement evidence. Composed installations can provide another backend implementing the same `EngagementStore` protocol so multiple Nights can share evidence without creating Night-to-Night runtime dependencies.

The portable store uses strict schema validation, immutable evidence IDs, conflict rejection, deterministic ordering, and atomic file replacement. Stored evidence remains context only: reading evidence from another Night never grants authorization to perform an active operation.
