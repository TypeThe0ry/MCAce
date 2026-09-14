# MCAce v0.0.1 executable verification previews

## rc1

- GitHub release: <https://github.com/TypeThe0ry/MCAce/releases/tag/v0.0.1-rc1>
- Release tag target: \`701c56f1465cadcff58456aec77bfd77213a0786\`
- Asset: \`MCAce-v0.0.1-701c56f-local-verification.zip\`
- Asset size: \`22,912,020\` bytes
- Asset SHA-256: \`7a1b605926b2259a7f9cd39e176f27ad4f6fceba4af504e3d61f41ce13ffa01a\`

The archive contains six deployable JARs plus \`release-manifest.properties\`
and \`SHA256SUMS\` for Fabric \`1.21.11\`, \`26.1.2\`, \`26.2\`, Velocity,
BungeeCord, and Paper/Folia. Its manifest is intentionally
\`MCACE_LOCAL_VERIFICATION_BUNDLE_V2\`, \`bundle_profile=LOCAL_VERIFICATION\`,
\`release_identity=false\`.

## rc2 current-source CI/Helio build

- Source commit: \`5a509ae2d268a7753fcb7963f68ca0f27c62459e\`
- GitHub CI push run: \`34860863487\` (success); PR run: \`34860869168\` (success).
- Helio Windows independent checkout build: success; \`clean build localVerificationBundle\`, exit 0.
- Helio job: \`C:\\CodexWorker\\jobs\\20260914-mcace-5a509ae-build\`
- Bundle: \`MCAce-v0.0.1-rc2-5a509ae-local-verification.zip\`
- Bundle size: \`22,912,018\` bytes
- Bundle SHA-256: \`77879ff3fd091bd0dc1d38c5f5681f2775cd3ebe2855e3e98c7fa915a2608e23\`
- Embedded identity: \`MCACE_LOCAL_VERIFICATION_BUNDLE_V2\`, \`bundle_profile=LOCAL_VERIFICATION\`, \`release_identity=false\`.

rc2 is executable and current-source, but remains a verification prerelease.
It is not evidence for the stable \`v0.0.1\` gates.

## rc3 current HEAD GitHub CI build

- Source commit: \`cf70818e86eabf4b62a88000183a6355a9510701\`.
- GitHub CI push run: \`34876228951\` (success); PR run: \`34876232834\` (success).
- Windows contracts: PowerShell 7 and Windows PowerShell 5.1 contract suites passed.
- Ubuntu build: \`clean build\` and the fully-offline \`localVerificationBundle\` job passed.
- Asset: \`MCAce-v0.0.1-rc3-cf70818-local-verification.zip\`.
- Asset size: \`22,912,017\` bytes.
- Asset SHA-256: \`6f53daa47698a47839d815aaaee90ad7d48f3615e2bf6018783db10caa39bc17\`.
- Embedded identity: \`MCACE_LOCAL_VERIFICATION_BUNDLE_V2\`,
  \`bundle_profile=LOCAL_VERIFICATION\`, \`release_identity=false\`.

rc3 is the earliest runnable preview built from the current HEAD. It is suitable for
early deployment/testing of the six JAR bundle, but it remains a prerelease and does
not close the stable GUI/Federation, licensed Vulcan, Production Authority, or
protected exact-release gates.
