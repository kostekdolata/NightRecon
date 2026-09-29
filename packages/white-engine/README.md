# White Night engine distribution

`nightrecon-white-engine` is the independently packaged White Night control-plane
engine.

The initial `0.1.0a1` package is intentionally a non-active foundation. It
defines White Night identity/capability metadata and an informational CLI surface
only. It does not scan targets, modify engagement authorization, grant approvals,
or execute another Night's capabilities.

The engine depends only on the mandatory `nightrecon-shared-core==0.41.0`
package. It does not depend on Red, Blue, Purple, Black, or the legacy
`nightrecon` distribution.

Future White batches will add engagement, ROE, approval, evidence-custody,
audit, exercise-control, and reporting behavior behind this package boundary.
The same engine package is intended for standalone, composed full-stack, and
White Night Live USB deployments.
