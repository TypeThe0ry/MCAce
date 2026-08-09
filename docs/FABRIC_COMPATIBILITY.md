# Fabric compatibility matrix

This matrix is an allowlist, not a claim that all Minecraft 1.21 releases are
binary-compatible. A version becomes supported only after the exact Loom build,
unit suite, real Fabric handshake smoke, and evidence cancellation/consent tests
pass for that version.

| Minecraft | Yarn | Fabric Loader | Fabric API | Status | Runtime evidence |
| --- | --- | --- | --- | --- | --- |
| 1.21.1 | 1.21.1+build.3 | 0.19.3 | 0.116.15+1.21.1 | Supported | Fabric → Velocity → Paper signed handshake and bounded evidence harness |
| Other 1.21.x | — | — | — | Not supported until an exact row passes | No compatibility claim |

## Release identity contract

- Build with `-PmcaceClientBuildId=<immutable-release-id>`.
- The processed `fabric.mod.json` contains the project version and build ID.
- The Mod reads its own processed metadata and the loaded Minecraft metadata; it
  does not use hard-coded source literals in the signed hello.
- Velocity and Bungee must sign policies containing the exact Minecraft version
  and build ID. Version/build migration may temporarily list both reviewed
  releases, but every list is bounded and duplicates are rejected.
- Reusing one build ID for different JAR bytes is an operator release error. The
  authenticated mod-manifest SHA-256 remains the independent content observation.

Adding a row requires updating the Loom dependency tuple, running the complete
Fabric/common/protocol suite, and recording a real process smoke report. Merely
changing the policy allowlist does not make an untested version supported.
