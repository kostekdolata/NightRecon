# v0.40.0 Cloud / Hybrid Intelligence

Red Night v0.40 adds an authorization-first cloud/hybrid ingestion boundary for
AWS, Azure, Entra, and Kubernetes evidence.

Read-only provider adapters return a strict normalized snapshot only after the
engagement policy authorizes `cloud.collect` for the provider-management
target. The schema accepts resource identifiers, display labels, identity
identifiers, and observed relationships; unexpected fields are rejected and
hard resource/identity/relationship/byte limits apply.

The importer emits the same `asset.observation`, `identity.observation`, and
`graph.relationship` evidence used by v0.36, so cross-provider relationships
join the unified graph without a second cloud-specific graph model. Missing
relationship endpoints remain unresolved and are not invented.

This milestone intentionally excludes cloud write operations, credential
harvesting, secret storage, persistence mechanisms, or privilege changes.
Concrete read-only AWS/Azure/Entra/Kubernetes adapters can now be developed
behind the tested provider contract.
