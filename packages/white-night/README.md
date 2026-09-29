# White Night application distribution

`nightrecon-white-night` is the separately installable White Night application
package.

The `0.1.0a4` development package includes immutable engagement/ROE, deterministic local policy compilation, and local approval-workflow operations. The command surface remains network-free and does not execute target activity. It
supplies the `white-night-app` entry point and depends on
`nightrecon-white-engine==0.1.0a4` plus the mandatory
`nightrecon-shared-core==0.41.0`.

It deliberately exposes only the informational `editions` command. White Night
must remain marked as not standalone-ready until the functional acceptance gates
in `WHITE_ACCEPTANCE.md` are satisfied.

The application package does not depend on Red, Blue, Purple, Black, or the
legacy `nightrecon` distribution. The same application/engine artifacts are
intended to be used for normal standalone installation, composed full-stack
installation, and White Night Live USB images.
