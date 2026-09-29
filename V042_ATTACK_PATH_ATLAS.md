# v0.42.0 Cross-Domain Attack Path Atlas

Red Night v0.42 begins the Cross-Domain Exposure Intelligence phase.

The first batch adds a deterministic, bounded path atlas over the existing
unified engagement graph. Its purpose is to let an operator review how evidence
from multiple specialist domains connects, without converting graph structure
into an exploitability or risk score.

## Scope

The atlas can begin from selected:

- identities
- groups
- network/cloud assets
- services

and follows directed graph evidence toward critical-asset nodes.

Because it operates on the unified graph, one returned path can cross evidence
from different domains, for example:

identity -> group -> permission -> host -> service -> cloud resource -> critical asset

The atlas does not create those graph facts. It only traverses facts already
present in the immutable graph.

## Evidence honesty

Every returned path records:

- deterministic path ID
- start and critical-target node IDs
- ordered node IDs
- ordered edge IDs
- ordered relationship names
- observed hop count
- inferred hop count
- engagement-evidence IDs supporting the path
- every non-secret provenance source type and source ID supporting its edges

Inferred edges remain explicitly inferred. The atlas does not relabel them as
observed.

The interpretation is fixed:

> Structural evidence review only; path presence and repeated participation do
> not establish exploitability, likelihood, impact, or risk.

## Structural participation

The atlas records node and edge participation counts across the returned path
set.

These counts are descriptive only. A node that appears in many paths is a
structural convergence point in the returned bounded graph search. Red Night
does not call it a risk score, probability, severity, exploitability score, or
automatic attack priority.

Start and final critical-target nodes are excluded from node participation so
the metric describes interior path convergence.

## Hard global ceilings

One atlas build uses global ceilings rather than multiplying a fresh exploration
budget for every start/target pair.

Defaults are:

- start nodes: 128
- critical targets: 64
- path depth: 6
- returned paths: 512
- graph expansions: 20,000

Queue growth is also constrained by the global expansion budget. Dense graphs
therefore cannot create unbounded pending BFS work.

When a ceiling affects the result, the atlas sets `truncated=true` and records
the applicable truncation reason.

## Optional relationship filter

A caller can restrict traversal to an explicit relationship allowlist. The
filter is normalized deterministically and rejects blank or duplicate values.

There is no wildcard query language or arbitrary execution surface.

## Deterministic benchmark

`tests/attack_path_atlas_runtime.py` builds one no-network unified graph with:

- Active Directory identity/group/permission evidence
- an on-premises asset and HTTPS service
- an Azure-style cloud resource and cloud identity
- a critical cloud application
- observed and inferred cross-domain relationships

The benchmark verifies:

- one long identity -> AD -> host -> service -> cloud -> critical path
- one direct cloud-identity -> cloud-resource -> critical path
- observed/inferred hop accounting
- evidence-ID preservation
- repeated cloud-resource participation
- deterministic repeated output
- no risk/exploitability score fields
- no human-readable identity/critical labels in the atlas payload

The benchmark runs in dedicated CI jobs on Python 3.11 and Python 3.14.

## Non-goals

This batch does not:

- infer missing graph edges
- claim exploitability
- rank risk
- execute validation
- execute commands or payloads
- choose an attack
- mutate an environment
- bypass engagement authorization

Later v0.42 batches will add evidence correlation rules, validation-candidate
compilation, cross-domain reporting, concrete cloud collectors, and reproducible
specialist-comparison labs.
