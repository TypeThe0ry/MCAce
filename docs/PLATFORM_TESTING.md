# Platform process testing

## Current release gates

MCAce has two independent platform gates:

1. `server-version-process-matrix.ps1` proves the raw Minecraft peer, proxy,
   backend, signed admission, shadow context, exact artifacts, and cleanup for
   all supported server tuples.
2. `platform-load-smoke.ps1 -FabricTarget ... -WithFabricEvidence` proves that
   the exact final Fabric artifact starts in a real graphical client and that a
   human sees and approves the two distinct consent prompts.

Neither gate replaces the other. The raw peer is bounded test tooling, not an
independent client product. A server-only platform run does not prove GUI consent.

## Exact compatibility contract

Before a process or GUI run, validate the release bundle itself:

```powershell
.\scripts\version-compatibility-contract-smoke.ps1 -Execute
.\scripts\version-compatibility-contract-smoke.ps1 -ReportOnly `
  -ReportPath .\build\compatibility-contract\report.json
```

This is an exact allowlist for `1.21.11`/774/JDK21, `26.1.2`/775/JDK25, and
`26.2`/776/JDK25. It verifies commit-bound `fabric.mod.json` metadata, final
remap versus final named artifact mode, nested-JAR shape, exact-eight bundle
membership, and explicit rejection of unlisted `1.21.x`/26.x patches. The
durable result is [`version-compatibility-contract-2026-08-21.json`](evidence/version-compatibility-contract-2026-08-21.json).

## Supported target and artifact matrix

| Minecraft | Protocol | Java | Paper | Folia | Fabric artifact |
| --- | ---: | ---: | --- | --- | --- |
| `1.21.11` | 774 | 21 | build 132, STABLE | build 14, STABLE | final remapped JAR |
| `26.1.2` | 775 | 25 | build 74, STABLE | build 8, STABLE | final named JAR |
| `26.2` | 776 | 25 | build 116, STABLE | build 6, **BETA** | final named JAR |

Both proxy assets are shared across the matrix:

| Platform | Version/build | SHA-256 |
| --- | --- | --- |
| Velocity | `3.5.1-615` | `b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3` |
| BungeeCord | `2085` | `e6914a29c0ae04c0ed6335f201e409322b3c67548906a91e92e832d665cd6fce` |

The backend pins are:

| Platform | Version/build | Channel | SHA-256 |
| --- | --- | --- | --- |
| Paper | `1.21.11-132` | STABLE | `5ffef465eeeb5f2a3c23a24419d97c51afd7dbb4923ff42df9a3f58bba1ccfba` |
| Paper | `26.1.2-74` | STABLE | `1d70b1dab9cf4a6de615209a536f3a45a2186240253c428213ce2188ab95e5f7` |
| Paper | `26.2-112` | STABLE | `bd3a58cf96874e5ea6643f5f6fe9b4f5bf9e34b795fa078c2f0ee8b98b2f907e` |
| Folia | `1.21.11-14` | STABLE | `f52c408490a0225611e67907a3ca19f7e6da2c6bc899e715d5f46844e7103c39` |
| Folia | `26.1.2-8` | STABLE | `607afd1c3320008e1ffd2eaee6780ace4419d5f8c527b75e79f259be79ebf57b` |
| Folia | `26.2-6` | BETA | `9a728381da3a3bea6732ee210519f8f6ab7d6affe132a430ee167c44c4603d08` |

Artifacts are pinned in `build/runtime-assets/manifest.json`. Initialized
server trees are bound by `build/runtime-assets/prepared-manifest.json`; only
`cache`, `libraries`, and `versions` are copied into a case. Worlds and live
state are never shared between cases.

## Run the 12-case server matrix

Use PowerShell 7 for execution:

```powershell
.\scripts\server-version-process-matrix.ps1 -Execute
.\scripts\server-version-process-matrix.ps1 -ReportOnly
```

The wrapper has no implicit mode. It fails unless exactly one of `-Execute` and
`-ReportOnly` is present. `-Execute`:

1. verifies the fixed asset and prepared-tree manifests;
2. resolves exact JDK 21, JDK 25, and Gradle 9.6.1 installations;
3. builds current Velocity, BungeeCord, and Paper/Folia MCAce plugins with root
   JDK 21 under strict offline, rerun, no-cache, serial flags;
4. executes 3 Minecraft versions × 2 backends × 2 proxies, one case at a time;
5. binds every case to current source, product JARs, server/proxy JARs, protocol
   profile, prepared-tree digest, and raw-report digest;
6. requires authentication, signed backend admission, the content-free shadow
   context audit, and zero run-owned processes;
7. rejects residual forwarding secrets, delegated keys, private keys, staging
   directories, or an incomplete evidence triplet; and
8. publishes `report.json`, `binding.json`, and `commit.json` by a same-volume
   atomic directory rename.

The current Helio run `2026-08-24T20-23-23-6783068Z` passed 12/12 and then passed
`-ReportOnly`: Paper 6/6, Folia 6/6, Velocity 6/6, Bungee 6/6, with 10 STABLE
cases and the two Folia 26.2 BETA cases. It binds 688 source files under manifest
`bcc0ead261ab3ee5924aeca7c54340753e94a515a3d683b768d445bda4aaf45d` on exact
code commit `395a769…`. Its current sanitized repository evidence is
[`evidence/server-version-process-matrix-2026-08-25-395a769.json`](evidence/server-version-process-matrix-2026-08-25-395a769.json).

`-ReportOnly` starts no server or proxy. It re-derives current source, asset,
prepared-tree, product-JAR, Java, Gradle, wrapper, and raw-report bindings and
accepts only the latest complete committed triplet. It rejects stale or partial
evidence and any binding drift.

## Run the per-target Fabric platform gate

`-FabricTarget` is mandatory:

```powershell
# Server-only startup. All three targets have passed this mode.
.\scripts\platform-load-smoke.ps1 -FabricTarget 1.21.11
.\scripts\platform-load-smoke.ps1 -FabricTarget 26.1.2
.\scripts\platform-load-smoke.ps1 -FabricTarget 26.2

# Real client and handshake, without frame evidence.
.\scripts\platform-load-smoke.ps1 -FabricTarget 1.21.11 -WithFabricClient

# Full visible consent/evidence gate.
.\scripts\platform-load-smoke.ps1 -FabricTarget 1.21.11 -WithFabricEvidence
```

The last command must be repeated for `26.1.2` and `26.2`. All three targets'
Mojang version metadata, asset indexes, and asset objects are already present in
the validated cache. There is no remaining asset-download blocker.

The human operator must approve two distinct UI decisions in each run:

1. the signed-policy explicit-file prompt; and
2. the later signed, one-shot `GAME_RENDER_FRAME` prompt.

That is six visible human clicks across three targets. A request marker emitted
before first render is not GUI evidence. The harness does not automate input,
does not control an existing Minecraft process, and cannot convert a decline,
close, expiry, or unsupported result into risk or enforcement.

A passing record uses report schema `6` and binding
`MCACE_FABRIC_GUI_EVIDENCE_BINDING_V4`. It must bind:

- the target-specific final artifact and unique run build ID;
- the loaded entrypoint's exact `CodeSource` SHA-256;
- the exact rewritten `velocity_policy_minecraft_versions` and
  `velocity_policy_client_build_ids` policy tuples;
- current Velocity and Paper plugin JARs;
- the pinned Velocity/Paper servers and prepared Paper tree;
- the Minecraft version manifest, asset index, and complete cached asset-object
  manifest;
- isolated `options.txt`, exactly one explicit-file manifest entry, both consent
  chains, bounded evidence transfer, and cleanup; and
- zero Java processes carrying the exact CSPRNG run token after cleanup.

For 1.21.11, artifact mode must be `FINAL_REMAP_JAR` /
`LOOM_FINAL_REMAP_ARTIFACT`. For 26.x it must be `FINAL_NAMED_JAR` /
`LOOM_FINAL_NAMED_JAR_ARTIFACT`. Development source output or a staged root
fallback cannot satisfy either mode.

Report-only validation requires the target and independently reviewed hashes:

```powershell
.\scripts\platform-load-smoke.ps1 -FabricTarget 26.2 -ReportOnly `
  -ExpectedFabricArtifactSha256 '<reviewed>' `
  -ExpectedVelocityPluginSha256 '<reviewed>' `
  -ExpectedPaperPluginSha256 '<reviewed>' `
  -ExpectedVelocityServerSha256 '<reviewed>' `
  -ExpectedPaperServerSha256 '<reviewed>' `
  -ExpectedPaperPreparedManifestSha256 '<reviewed>' `
  -ExpectedPaperPreparedTreeSha256 '<reviewed>' `
  -ExpectedFabricVersionInfoSha256 '<reviewed>' `
  -ExpectedFabricAssetIndexSha256 '<reviewed>' `
  -ExpectedFabricAssetObjectManifestSha256 '<reviewed>'
```

Do not source the expected values from the report being validated.

## Other retained process gates

The following opt-in gates remain valid for the narrow contracts stated in
their own retained evidence, but they do not add Fabric-version support:

- `disposition-proxy-matrix-smoke.ps1 -Proxy Both -FabricTarget <1.21.11|26.1.2|26.2>`:
  8/8 CLIENT_REPORTED advisory-origin guard per target; no requested
  high-impact action executes. Repeat once for each target; retained 2026-08-13
  evidence is historical until a current-source Execute+ReportOnly pair exists.
- `trusted-disposition-proxy-matrix-smoke.ps1 -Proxy Both -FabricTarget <1.21.11|26.1.2|26.2>`:
  6/6 ADMIN_REVIEWED V4 routes per target; LIMIT and QUARANTINE are distinct
  and DENY closes only the current connection. Repeat once for each target;
  retained 2026-08-13 evidence is historical until refreshed.
- `federation-proxy-matrix-smoke.ps1 -Pair All`: 4/4 raw-peer federation
  protocol/audit matrix. `fabric_gui_coverage=false` remains true.
- `federation-target-restart-residual-smoke.ps1`: process-local replay-state
  residual characterization; it truthfully records
  `durable_replay_protection=false`.

The separate Fabric federation V2 wrapper and both visible screens are
implemented for all three targets. Its PowerShell 7 and Windows PowerShell 5
static contract tests pass, including the six exact source-export/target-import
runtime markers. A real run still needs a human to approve source export,
disconnect and directly join the exact target, approve target import, and keep
the target connection alive through signed expiry. Raw-peer or static evidence
cannot be promoted to that coverage.

## Legacy wrappers and historical evidence

The following wrappers and their Minecraft 1.21.1/1.21.4 records predate the
three-version matrix:

- `bungee-paper-load-smoke.ps1`;
- `folia-process-smoke.ps1`;
- `proxy-admission-player-smoke.ps1`;
- `proxy-folia-context-smoke.ps1`; and
- `paper-folia-hostile-admission-smoke.ps1`, whose version allowlist is still
  limited to the older 1.21.1–1.21.4 range.

They are retained as legacy debugging or historical evidence only. Their old
Paper 1.21.1-133, BungeeCord 2028, and Folia 1.21.4-6 ALPHA pins are not current
release inputs and cannot satisfy the 1.21.11/26.1.2/26.2 release gate.

## Evidence boundary

Current process evidence proves loopback/offline process behavior for exact
reviewed artifacts. It does not prove Mojang/Microsoft online-mode identity,
public-network forwarding, production firewall/ACL policy, a licensed Vulcan
event, or a live SERVER_CONFIRMED producer. Context remains shadow-only and has
no disposition callback. Fabric evidence remains CLIENT_REPORTED. `MONITOR`
remains the default, no permanent automatic BAN exists, and DENY is limited to
the current connection.
