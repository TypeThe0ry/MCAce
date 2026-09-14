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

The six JAR bytes for the final core bundle are produced from artifact source
commit `d2d1aaafc09283598f005ab3dc5b70ab05f9d032`, which is the merged main
release source recorded in the canonical marker
`docs/evidence/release-artifact-source.txt`. The earlier build provenance
commit `7db0b7ff28cce534ecafa1d1f40b6541271a2f14` remains historical evidence
for the pre-merge candidate; it is not the source selector for the final
bundle. The bundle manifest records the final release and artifact identities.

The provenance marker is intentionally updated on the merged-main lineage so
protected CI can resolve the artifact source after a squash merge.
The protected `main` and `v0.0.1` workflows rebuild the bundle from this
marker; they do not reuse the pre-merge candidate bytes.

## Extended certification

The strict `release-readiness.ps1` flow remains available and fail-closed for
GUI/Federation V5, licensed Vulcan, Production Authority, and externally
supervised Matrix evidence. Those witnesses are not fabricated or relabeled by
this core release. Their status remains `PENDING_EXTERNAL_EVIDENCE` in the
core readiness report until genuine external artifacts are supplied.
