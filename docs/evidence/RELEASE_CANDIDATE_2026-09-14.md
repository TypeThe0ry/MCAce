# MCAce v0.0.1-rc1 executable preview

- GitHub release: <https://github.com/TypeThe0ry/MCAce/releases/tag/v0.0.1-rc1>
- Release tag target: `701c56f1465cadcff58456aec77bfd77213a0786`
- Asset: `MCAce-v0.0.1-701c56f-local-verification.zip`
- Asset size: `22,912,020` bytes
- Asset SHA-256: `7a1b605926b2259a7f9cd39e176f27ad4f6fceba4af504e3d61f41ce13ffa01a`

The archive contains the six deployable JARs plus `release-manifest.properties`
and `SHA256SUMS` for the three Fabric targets (`1.21.11`, `26.1.2`, `26.2`)
and Velocity, BungeeCord, and Paper/Folia server plugins.

The embedded manifest is intentionally `MCACE_LOCAL_VERIFICATION_BUNDLE_V2`,
with `bundle_profile=LOCAL_VERIFICATION` and `release_identity=false`. This
preview is executable for early deployment and integration work; it is not the
stable `v0.0.1` release and does not satisfy the repository's external GUI,
Federation V5, Vulcan V3, Production Authority V4, Matrix exact-source, or
protected-release CI gates.
