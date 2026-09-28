# Fabric Mojang asset pin refresh — 2026-09-29

This record explains why the reviewed Mojang version-info and asset-index pins in
`scripts/platform-load-smoke.ps1` changed, and what was reviewed before the change.
It does not close any release gate by itself.

## Symptom

Every client smoke (`-WithFabricClient`, `-WithFabricEvidence`, and the Federation V5
wrapper that reuses `Assert-FabricAssetCache`) failed before any build or process
start with:

```text
PLATFORM_SMOKE_FABRIC_VERSION_INFO_PIN_MISMATCH: 1.21.11
PLATFORM_SMOKE_FABRIC_VERSION_INFO_PIN_MISMATCH: 26.2
```

## Root cause

Mojang republished the version metadata for 1.21.11, 26.1.2, and 26.2 with a new
asset index. Any online Gradle run lets Loom overwrite the shared
`%USERPROFILE%\.gradle\caches\fabric-loom\<version>\mojang_minecraft_info.json`
with the current upstream object. The smoke runs Gradle `--offline` and verifies
that file before building, so it failed closed before a client could launch.

Restoring only the old JSON cannot work: Loom validates the version file against
its cached `mojang_versions_manifest.json`, which already carries the new SHA-1.

## Reviewed drift

The old and new objects were both fetched from `piston-meta.mojang.com` and
verified by SHA-1. The version JSON differs **only** in `assetIndex`
(same `id` and `size`, new `sha1`/`totalSize`). The asset index differs in exactly
144 objects per version, with no objects added or removed:

| Asset group | Changed objects | Review |
| --- | ---: | --- |
| `minecraft/lang/*.json` | 142 | Translation updates |
| `minecraft/resourcepacks/high_contrast.zip` | 1 | Same size; identical entry names and CRC-32 values (repackaged bytes only) |
| `minecraft/resourcepacks/programmer_art.zip` | 1 | Same size; identical entry names and CRC-32 values (repackaged bytes only) |

No game code, library, or texture/model/sound content changed.

## New pins

| Target | Version-info SHA-1 | Version-info SHA-256 | Asset index (id, SHA-1, size) |
| --- | --- | --- | --- |
| 1.21.11 | `bc03bf4398acc192063d758aecb1cb299f05d793` | `13e195800429ad001c3d897dd646638b2bc9a9fc5ce01d840d440eb0f2ea5351` | `29`, `adb0a43fae291fd88ee27d85a372ba6f2072b0a3`, 529966 |
| 26.1.2 | `50187e15f4fe9e772e617db26c58d789f9ec2b31` | `2e7b23dcfb78ab3921ea663347be48508cbb286756d2b46027b47008a006c85c` | `30`, `1cf55e789e49796e91b0258d4012e653b0e6acc3`, 548391 |
| 26.2 | `33c420747ce582e48dff1d8c5d8e67e5bb6257c9` | `aaeca0a201d12c0d2259a7afe137099b1318602c073a17deccc77c7767d2f8c6` | `32`, `52695890153d94cf946455da532806db8c530831`, 586366 |

The local Loom cache was brought to these objects by downloading the index and
every missing object from Mojang with SHA-1 and size verification (1.21.11: 144
objects, 26.1.2 and 26.2: 2 objects each, the rest were already shared).

The mismatch error now reports `observed_sha1` and `reviewed_sha1`, so the next
upstream republish can be diagnosed and reviewed without rerunning the smoke.

## Validation

Contract tests (Windows PowerShell 5.1 and PowerShell 7.6):

```text
scripts/test-platform-load-smoke-privacy.ps1       PLATFORM_LOAD_SMOKE_PRIVACY_STATIC_PASS
scripts/test-fabric-federation-gui-handoff-smoke.ps1 FABRIC_FEDERATION_GUI_HANDOFF_STATIC_V5_PASS_WITH_SYMLINK_PERMISSION_GAP
scripts/test-release-readiness.ps1                 RELEASE_READINESS_V5_PASS_WITH_SYMLINK_PERMISSION_GAP
```

Real unattended client smokes with the new pins, all three targets:

```powershell
$env:MCACE_JAVA21_HOME = 'D:\MCAceTools\jdk\jdk-21'
$env:MCACE_JAVA25_HOME = 'D:\MCAceTools\jdk\jdk-25'
.\scripts\platform-load-smoke.ps1 -FabricTarget <1.21.11|26.1.2|26.2> -WithFabricClient -RetainDiagnostics
```

For 1.21.11, 26.1.2, and 26.2 the asset-cache check passed, the offline Gradle
build and artifact verification succeeded, Velocity and Paper started, and the
Fabric client loaded the freshly built MCAce artifact
(`MCACE_FABRIC_ARTIFACT_LOADED`), connected through the proxy, received the signed
handshake, and rendered the enablement screen. Nobody was at the desktop, so every
run failed closed exactly as designed:

```text
enablement_consent_requested = true
enablement_consent_rendered  = true
enablement_consent_accepted  = false
fabric_authenticated         = false
PLATFORM_LOAD_SMOKE_FAILURE|Fabric MCAce enablement screen rendered but was not approved before the 30-second smoke handshake timeout
```

No input was synthesized. This only proves the current-source client reaches the
visible `Enable MCAce` screen again; the single human-approved confirmation and the
externally signed GUI attestation described in [RELEASE_GATES.md](../RELEASE_GATES.md)
remain pending.
