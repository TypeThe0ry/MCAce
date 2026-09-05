# Fabric compatibility matrix

This is an exact allowlist. MCAce does not infer compatibility from a nearby
Minecraft release, a broad `1.21.x` range, or a successful server-only run.

| Minecraft | Namespace / artifact | Java | Fabric Loader | Fabric API | Packaging state | Remaining GUI gate |
| --- | --- | ---: | --- | --- | --- | --- |
| `1.21.11` | Yarn/remapped; final `remapJar` | 21 | `0.19.3` | `0.141.6+1.21.11` | Build, final-artifact isolation, and package verification passed; retained Matrix V1 process diagnostic only | One selected version receives the sole source-side release approval; otherwise this row is a non-promoting compatibility smoke |
| `26.1.2` | Official named namespace; final named JAR | 25 | `0.19.3` | `0.155.2+26.1.2` | Build, final-artifact isolation, and package verification passed; retained Matrix V1 process diagnostic only | One selected version receives the sole source-side release approval; otherwise this row is a non-promoting compatibility smoke |
| `26.2` | Official named namespace; final named JAR | 25 | `0.19.3` | `0.157.0+26.2` | Build, final-artifact isolation, and package verification passed; retained Matrix V1 process diagnostic only | One selected version receives the sole source-side release approval; otherwise this row is a non-promoting compatibility smoke |

The retained historical server-process diagnostic is the Helio Execute+ReportOnly
12/12 Matrix V1 record
at [`evidence/server-version-process-matrix-2026-08-25-f404971.json`](evidence/server-version-process-matrix-2026-08-25-f404971.json),
with the immutable report/binding/commit triplet under
[`evidence/server-version-process-matrix/2026-08-24T21-33-47-1914356Z/`](evidence/server-version-process-matrix/2026-08-24T21-33-47-1914356Z/).
It binds 686 source files from its exact historical snapshot, all three protocol
profiles, and the reviewed upstream artifacts. It is not current Matrix V4 or
release evidence. Paper 26.2 build 116 is STABLE; only the two Folia 26.2
combinations use the upstream BETA lane (build 6).

The root build is configured and executed by JDK `21.0.7+6`. The isolated
`fabric-modern/` composite is configured and executed by JDK `25.0.3+9`; it
must not inherit the root Java runtime. Both use Gradle `9.6.1`. The 26.x
projects use Mojang's official named namespace and publish their final named JAR
directly. The 1.21.11 project remains a Loom remap build and publishes the final
remapped JAR.

Each generated `fabric.mod.json` pins its own Minecraft and Fabric API tuple and
requires Fabric Loader `>=0.19.3`; every documented release tuple is built and
process-tested with Loader `0.19.3`. The build opens each deployable, checks the
embedded common/core/SDK/protocol dependencies, rejects unresolved production
class references and metadata placeholders, and verifies that the run-specific
build ID is present. The GUI harness then requires the loaded entrypoint's
`CodeSource` SHA-256 to equal the pre-launch final-artifact hash. Development
output directories and fallback MCAce JARs cannot satisfy artifact mode.

## GUI consent gate

Compatibility wrappers always require an explicit target:

```powershell
# Three non-promoting compatibility smokes; these do not mint GUI approval.
.\scripts\platform-load-smoke.ps1 -FabricTarget 1.21.11
.\scripts\platform-load-smoke.ps1 -FabricTarget 26.1.2
.\scripts\platform-load-smoke.ps1 -FabricTarget 26.2

# Choose exactly one representative target for the sole visible source decision.
$representativeTarget = '1.21.11' # or 26.1.2 / 26.2
.\scripts\platform-load-smoke.ps1 -FabricTarget $representativeTarget -WithFabricEvidence
```

The standalone `-WithFabricEvidence` run is a local GUI diagnostic. Release
evidence is minted only when that same selected target and one source-side
decision are captured by the Federation V5 wrapper as an externally signed
eight-file package with `MCACE_VISIBLE_GUI_ATTESTATION_V3`; target import opens no
second prompt. Running `-WithFabricEvidence` on either unselected version is an
optional non-promoting UI compatibility smoke, not another approval.

All three Mojang version manifests, asset indexes, and asset-object sets are
already present in the verified local cache. That removes asset download as a
blocker. It does not replace the human gate: the reviewed client shows one
visible connection-level MCAce enablement decision. The explicit-file,
render-frame, and federation paths inherit that decision, so the reviewed
three-target compatibility matrix requires no repeated approvals. Automation
must not manufacture the one source-side decision.

A passing retained pair uses report schema `8` and binding schema
`MCACE_FABRIC_GUI_EVIDENCE_BINDING_V6`. `-ReportOnly` also requires
`-FabricTarget` plus independently reviewed SHA-256 values for the Fabric
artifact, both MCAce server plugins, Velocity, Paper, the prepared Paper tree,
and the target's Minecraft asset bindings. It also binds the exact rewritten
Velocity policy values in `velocity_policy_minecraft_versions` and
`velocity_policy_client_build_ids`. The 1.21.11 record must identify
`FINAL_REMAP_JAR` / `LOOM_FINAL_REMAP_ARTIFACT`; both 26.x records must identify
`FINAL_NAMED_JAR` / `LOOM_FINAL_NAMED_JAR_ARTIFACT`.

## Release identity contract

- Local dirty-worktree verification uses `localVerificationBundle`; its manifest
  is `MCACE_LOCAL_VERIFICATION_BUNDLE_V1`, records
  `source_commit=LOCAL_UNSPECIFIED`, and is never release identity.
- A release candidate uses `releaseBundle` with
  `-PmcaceSourceCommit=<40-lowercase-hex-HEAD>`. The task requires a clean
  tracked and untracked worktree and exact equality with `git rev-parse HEAD`.
- Every Fabric target receives its own immutable build ID:
  `fabric-1.21.11-<commit>`, `fabric-26.1.2-<commit>`, or
  `fabric-26.2-<commit>`.
- Velocity policy allowlists must name exact Minecraft versions and build IDs; a
  staged migration may use bounded, duplicate-free reviewed lists. Bungee's
  built-in configuration accepts one exact Minecraft version and one exact build
  ID per proxy configuration, so select the target-matched tuple there rather
  than using comma-separated values.
- Reusing one build ID for different JAR bytes is an operator release error. The
  authenticated manifest/content-root remains a separate observation.

Adding a target requires an exact dependency tuple, a final-artifact verification
task, the complete client/common/protocol suite, all four real proxy/backend
matrix cases for that version, server-only platform startup, and the one visible
connection-level enablement decision. Editing only a policy allowlist does not
add support.
