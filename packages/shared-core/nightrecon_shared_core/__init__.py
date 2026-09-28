"""Shared, network-free policy surface for independently installable Night apps."""

from nightrecon_shared_core.authorization import Scope, Target, TargetType, parse_target
from nightrecon_shared_core.contracts import (
    EngagementEnvelope,
    EngagementMetadata,
    EvidenceRecord,
)
from nightrecon_shared_core.engagement_policy import (
    AuthorizationAuditRecord,
    AuthorizationDecision,
    EngagementExecutionPolicy,
    FileEngagementPolicyStore,
    evaluate_action,
)
from nightrecon_shared_core.editions import (
    EDITIONS,
    Edition,
    EditionRouteError,
    available_commands,
    edition_name,
)
from nightrecon_shared_core.file_store import FileEngagementStore
from nightrecon_shared_core.store import (
    EngagementStore,
    EvidenceConflictError,
    InMemoryEngagementStore,
    MetadataConflictError,
)
from nightrecon_shared_core.workspace import (
    EvidenceBreakdown,
    LocalWorkspace,
    MergeReport,
    WorkspaceStore,
    WorkspaceSummary,
)

__all__ = [
    "EDITIONS", "AuthorizationAuditRecord", "AuthorizationDecision",
    "Edition", "EditionRouteError", "EngagementEnvelope",
    "EngagementExecutionPolicy",
    "EngagementMetadata", "EngagementStore", "EvidenceBreakdown",
    "EvidenceConflictError", "EvidenceRecord", "FileEngagementPolicyStore",
    "FileEngagementStore",
    "InMemoryEngagementStore", "LocalWorkspace", "MergeReport",
    "MetadataConflictError", "Scope", "Target", "TargetType",
    "WorkspaceStore", "WorkspaceSummary", "available_commands",
    "evaluate_action",
    "edition_name", "parse_target",
]
