# Core v0.0.1 release record

This record defines the early executable release boundary requested for MCAce.
It is intentionally separate from the strict extended-certification ledger.

## Core contract

- Six deployable artifacts: three Fabric clients, Velocity, BungeeCord, and
  Paper/Folia.
- Exact supported targets: `1.21.11`, `26.1.2`, and `26.2`.
- `MCACE_RELEASE_BUNDLE_V4` manifest, eight-entry bundle, SHA-256 sums, and
  source/artifact commit binding.
- Protected GitHub `build` workflow runs the Windows contracts, Linux build,
  compatibility contract, and `core-release-readiness.ps1` on `main` and the
  `v0.0.1` tag.

## Artifact source

The six JAR bytes are produced from artifact source commit
`7db0b7ff28cce534ecafa1d1f40b6541271a2f14`. The final release commit may be a
documentation/evidence-only descendant; the bundle manifest records both
identities and the canonical marker is
`docs/evidence/release-artifact-source.txt`.

## Extended certification

The strict `release-readiness.ps1` flow remains available and fail-closed for
GUI/Federation V5, licensed Vulcan, Production Authority, and externally
supervised Matrix evidence. Those witnesses are not fabricated or relabeled by
this core release. Their status remains `PENDING_EXTERNAL_EVIDENCE` in the
core readiness report until genuine external artifacts are supplied.
