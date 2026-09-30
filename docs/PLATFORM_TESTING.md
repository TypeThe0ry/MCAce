# Platform process testing

## Current release gates

MCAce has two independent platform gates:

1. `server-version-process-matrix.ps1` proves the raw Minecraft peer, proxy,
   backend, signed admission, shadow context, exact artifacts, and cleanup for
   all supported server tuples.
2. `platform-load-smoke.ps1 -FabricTarget ... -WithFabricEvidence` proves that
   the exact final Fabric artifact starts in a real graphical client and that a
   human sees and approves one connection-level enablement prompt.

Neither gate replaces the other. The raw peer is bounded test tooling, not an
independent client product. A server-only platform run does not prove GUI consent.

## Exact compatibility contract

Before a process or GUI run, validate the release bundle itself:

```powershell
.\scripts\version-compatibility-contract-smoke.ps1 -Execute
.\scripts\version-compatibility-contract-smoke.ps1 -ReportOnly `
  -ReportPath .\build\compatibility-contract\report.json
```

This is an exact allowlist for `1.21.11`/774/JDK21, `26.1.2`/775/JDK25,
`26.2`/776/JDK25, and `26.3`/777/JDK25. It verifies commit-bound
`fabric.mod.json` metadata, final remap versus final named artifact mode,
nested-JAR shape, exact-nine bundle membership (seven deployable JARs), and
explicit rejection of unlisted `1.21.x`/26.x patches. The retained durable
result [`version-compatibility-contract-2026-08-21.json`](evidence/version-compatibility-contract-2026-08-21.json)
predates `26.3` and covers the three original targets.

## Supported target and artifact matrix

| Minecraft | Protocol | Java | Paper | Folia | Fabric artifact |
| --- | ---: | ---: | --- | --- | --- |
| `1.21.11` | 774 | 21 | build 132, STABLE | build 14, STABLE | final remapped JAR |
| `26.1.2` | 775 | 25 | build 74, STABLE | build 8, STABLE | final named JAR |
| `26.2` | 776 | 25 | build 116, STABLE | build 6, **BETA** | final named JAR |
| `26.3` | 777 | 25 | build 140, **BETA** (experimental) | none upstream | final named JAR |

The server-version process matrix defines 14 cases: Paper and Folia for
`1.21.11`/`26.1.2`/`26.2`, plus an explicit experimental, Paper-only `26.3`
lane (Folia publishes no `26.3` line). The `26.3` cases bind Velocity
`4.2.0-30` (Java 25) and BungeeCord `2100`, because Velocity `3.5.1-615` and
BungeeCord `2085` predate protocol 777; the three original targets keep those
reviewed proxies. Paper `26.3` has no STABLE build, so its two cases are
labelled BETA alongside Folia `26.2` (10 STABLE + 4 BETA) and are never
promoted. The platform smoke fails closed for `26.3`
(`PLATFORM_SMOKE_EXPERIMENTAL_SERVER_LANE_NOT_ALLOWED`) unless the operator
passes `-AllowExperimentalServerLane`; see the per-target gate below.

Reviewed proxy assets (each case selects the pin whose target set contains its version):

| Platform | Version/build | Targets | SHA-256 |
| --- | --- | --- | --- |
| Velocity | `3.5.1-615` | `1.21.11`, `26.1.2`, `26.2` | `b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3` |
| Velocity | `4.2.0-30` (Java 25) | `26.3` | `35a5596a5468a035d8a32c8de5ebb0dc6b8d8f0cc3ff5169d514aca762af8aa8` |
| BungeeCord | `2085` | `1.21.11`, `26.1.2`, `26.2` | `e6914a29c0ae04c0ed6335f201e409322b3c67548906a91e92e832d665cd6fce` |
| BungeeCord | `2100` | `26.3` | `8b9f75994fa6bd027e98827b3f83523f462c9e4b978fdab2fad00182ba4c924b` |

The backend pins are:

| Platform | Version/build | Channel | SHA-256 |
| --- | --- | --- | --- |
| Paper | `1.21.11-132` | STABLE | `5ffef465eeeb5f2a3c23a24419d97c51afd7dbb4923ff42df9a3f58bba1ccfba` |
| Paper | `26.1.2-74` | STABLE | `1d70b1dab9cf4a6de615209a536f3a45a2186240253c428213ce2188ab95e5f7` |
| Paper | `26.2-116` | STABLE | `17eee738bc0f6b747646be4199672c4efcb2084efd7e291ec5254a45d5ae6f2e` |
| Paper | `26.3-140` | BETA (experimental) | `98aabc113a80b9b5e183475e839a17cf99c39c915a1f46b8f35a5e89fd5de0f1` |
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

The retained historical Helio run `2026-08-24T21-33-47-1914356Z` passed 12/12 and then passed
`-ReportOnly`: Paper 6/6, Folia 6/6, Velocity 6/6, Bungee 6/6, with 10 STABLE
cases and the two Folia 26.2 BETA cases. It binds 686 source files under manifest
`db15e9707ac1deb87958f0d031fe3946d9bbf961ba01844550983fd5f8fcec72` on exact
code commit `f404971…`. Its retained sanitized repository evidence is
[`evidence/server-version-process-matrix-2026-08-25-f404971.json`](evidence/server-version-process-matrix-2026-08-25-f404971.json).
That Matrix V1 record is commit-bound diagnostic history, not current-working-tree
or Matrix V4 release evidence.

`-ReportOnly` starts no server or proxy. It re-derives current source, asset,
prepared-tree, product-JAR, Java, Gradle, wrapper, and raw-report bindings and
accepts only the latest complete committed triplet. It rejects stale or partial
evidence and any binding drift.

## Run the per-target Fabric platform gate

`-FabricTarget` is mandatory:

```powershell
# Server-only startup. The three original targets have passed this mode;
# no 26.3 run is recorded.
.\scripts\platform-load-smoke.ps1 -FabricTarget 1.21.11
.\scripts\platform-load-smoke.ps1 -FabricTarget 26.1.2
.\scripts\platform-load-smoke.ps1 -FabricTarget 26.2

# Real client and handshake, without frame evidence.
.\scripts\platform-load-smoke.ps1 -FabricTarget 1.21.11 -WithFabricClient

# Optional local GUI compatibility diagnostic on one selected target. This does
# not mint or promote the single Federation V5 release approval.
.\scripts\platform-load-smoke.ps1 -FabricTarget 1.21.11 -WithFabricEvidence

# Experimental 26.3 lane (explicit opt-in; never STABLE or release evidence).
.\scripts\platform-load-smoke.ps1 -FabricTarget 26.3 -WithFabricClient -AllowExperimentalServerLane
```

`-AllowExperimentalServerLane` (Execute only) admits exactly the reviewed
matrix lane: Velocity `4.2.0-30` selected from the manifest by
`target_versions` and checked against the smoke's reviewed pin table, plus
Paper `26.3` build `140` channel BETA. Velocity runs on the exact target JDK
(Java 25 for 26.x; the 4.2.0-30 pin requires Java 25). Stable targets resolve
identically with or without the switch. The report and binding record
`server_lane = 'EXPERIMENTAL_BETA'` and `velocity_server_version`, keep
`release_evidence = false`, and `-ReportOnly` (which cannot take the switch)
rejects an experimental report with
`PLATFORM_SMOKE_REPORT_EXPERIMENTAL_SERVER_LANE_NOT_STABLE_EVIDENCE`.

The `-WithFabricEvidence` command is not a per-target release requirement. The `26.1.2` and
`26.2` clients may receive separate UI compatibility or visual diagnostics when
needed, but those runs are not second or third release approvals and cannot mint
or promote release consent. The three original targets' Mojang version metadata, asset
indexes, and asset objects are already present in the validated cache, so there
is no remaining asset-download blocker.

Release acceptance uses exactly one human-origin, source-side, visible,
connection-bound `Enable MCAce` decision inside the Federation V5 handoff. The
target inherits that decision and opens no second prompt. A request marker emitted
before first render is not GUI evidence. Neither wrapper automates input or
controls an existing Minecraft process, and neither may convert a decline, close,
expiry, or unsupported result into risk or enforcement.

A passing record uses report schema `9` and binding
`MCACE_FABRIC_GUI_EVIDENCE_BINDING_V7`. It must bind:

- the target-specific final artifact and unique run build ID;
- the loaded entrypoint's exact `CodeSource` SHA-256;
- the exact rewritten `velocity_policy_minecraft_versions` and
  `velocity_policy_client_build_ids` policy tuples;
- current Velocity and Paper plugin JARs;
- the server lane (`STABLE` or `EXPERIMENTAL_BETA`), the pinned Velocity/Paper
  servers, and the prepared Paper tree;
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
- Neither disposition wrapper has a recorded `26.3` run.
- `federation-proxy-matrix-smoke.ps1 -Pair All`: 4/4 raw-peer federation
  protocol/audit matrix. `fabric_gui_coverage=false` remains true.
- `federation-target-restart-residual-smoke.ps1`: process-local replay-state
  residual characterization; it truthfully records
  `durable_replay_protection=false`.

The Fabric Federation V5 wrapper is implemented for the three original targets
(`1.21.11`, `26.1.2`, `26.2`); no `26.3` run is recorded. Its
PowerShell 7 and Windows PowerShell 5 parser/static contract tests pass. A real
run still needs one independently attested visible `Enable MCAce` decision at the
source, followed by source authorization, source disconnect, direct join to the
exact target with no second prompt, and a live target connection through signed
expiry. The exact eight-file native set is report, binding, commit, the runner-
generated GUI signing request, `MCACE_VISIBLE_GUI_ATTESTATION_V3`, decoded PNG,
sealed runtime ledger, and the distinct post-run supervisor receipt. The GUI
signer and post-run supervisor must use independently approved, different roots;
the complete set must survive V5 publication/readiness validation. Raw-peer,
fixture, equal-key, self-approved, or static evidence cannot be promoted to that
coverage.

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
release inputs and cannot satisfy the 1.21.11/26.1.2/26.2/26.3 release gate.

## Evidence boundary

Current process evidence proves loopback/offline process behavior for exact
reviewed artifacts. It does not prove Mojang/Microsoft online-mode identity,
public-network forwarding, production firewall/ACL policy, a licensed Vulcan
event, or a live SERVER_CONFIRMED producer. Context remains shadow-only and has
no disposition callback. Fabric evidence remains CLIENT_REPORTED. `MONITOR`
remains the default, no permanent automatic BAN exists, and DENY is limited to
the current connection.
