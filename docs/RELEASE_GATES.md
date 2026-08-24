# MCAce release gates

Status snapshot: August 25, 2026. Files below `build/` are mutable diagnostics.
Only the bounded records copied to `docs/evidence/` are durable repository
evidence, and a passing local record is not automatically an exact-commit release.

## Product boundary

The release product is exactly:

- Fabric client Mods for `1.21.11`, `26.1.2`, and `26.2`;
- Velocity and BungeeCord proxy plugins;
- one Paper/Folia backend plugin.

Cloud, Portal, PostgreSQL, and Launcher remain frozen legacy/optional source. No
Agent, additional loader, standalone client, mandatory Cloud service, desktop or
window capture, permanent automatic ban, or reconnect-spanning DENY is part of
the release. `MONITOR` is the default. DENY closes only the current connection.

The distribution boundary is exact-eight: six deployable JARs,
`release-manifest.properties`, and `SHA256SUMS`. The strict offline records use
JDK `21.0.7+6` and isolated modern JDK `25.0.3+9`; the current Helio exact-
commit candidate uses JDK `21.0.10` and modern JDK `25.0.4.1`. Both paths use
Gradle `9.6.1`. Root verification metadata contains 47 exact Loom-local trust entries
and `fabric-modern` contains two exact named-Minecraft trust entries. There is no
group-wide trust. The superseded 52-rule, exact-six, four-JAR Linux rehearsal is
historical only and cannot be promoted to the current three-version release.

## Gate matrix

| Gate | State | Current evidence | Release interpretation |
| --- | --- | --- | --- |
| Strict offline Windows reproducibility | Passed locally | [`local-build-2026-08-20.json`](evidence/local-build-2026-08-20.json); independent clean August 20 A/D runs each completed 118/118 tasks. Root: 147 suites / 681 tests / 0 failures / 0 errors / 28 skipped. Modern: 24 / 74 / 0 / 0 / 0. Combined: 171 / 755 / 0 / 0 / 28. Exact-eight A/D bytes match. | Strong sanitized local reproducibility evidence. The manifest is `LOCAL_VERIFICATION`, `release_identity=false`, and `source_commit=LOCAL_UNSPECIFIED`; it is not a release candidate. |
| Linux network-none rehearsal | Passed for current boundary | [`local-build-2026-08-20.json`](evidence/local-build-2026-08-20.json), run `cb6dc44ddad744b5a20dc2986c0a6d70`; strict offline network-none; exact JDK 21.0.7+6/JDK 25.0.3+9; 118 root actionable tasks plus 15/15 modern tasks; 171 suites / 755 tests / 0 failures / 0 errors / 33 environment-conditioned skips; unchanged 735-file source manifest; all eight entries stream-byte-identical to Windows A/D; cleanup zero at 0/30/60 seconds. | Current Linux parity is proven for the LOCAL exact-eight boundary. The detailed raw witness remains external; the repository record is sanitized. This is not exact-commit release identity. |
| GitHub Actions / exact commit | Passed for feature source `42f80b74c182b6a16b0e9afa57e48e34ce487c56`; protected-main release path pending | [Push run `32757636048`](https://github.com/TypeThe0ry/MCAce/actions/runs/32757636048) and [PR run `32757641327`](https://github.com/TypeThe0ry/MCAce/actions/runs/32757641327), with sanitized [evidence](evidence/github-feature-ci-2026-08-25-42f80b7.json), passed exact checkout, build/test, local-verification bundle, and exact-eight upload; releaseBundle and the main-only readiness gate were correctly skipped on the feature branch. | Current feature witness is green. Merge to protected `main` only after external gates close, then rerun exact-commit CI/releaseBundle and verify the eight-file artifact before tagging. |
| Latest recorded exact-commit CI / release bundle | Passed for merged source `f355a85f65173c6e98ab685e3b36f5e172b85498` | Run [`32570987482`](https://github.com/TypeThe0ry/MCAce/actions/runs/32570987482) verified the exact checkout, ran build/test, built the exact release candidate, uploaded all eight entries, and passed local SHA256 verification. See [`release-bundle-2026-08-22-f355a85.json`](evidence/release-bundle-2026-08-22-f355a85.json). | This immutable source is green. Any later source/documentation commit must receive its own required `build` check before tagging. |
| Helio exact-commit release candidate | Passed for immutable source `e7f6f74a9d08b6c4cef829b7b5e65ba150f5d834` | [`release-bundle-e7f6f74.json`](evidence/release-bundle-e7f6f74.json) records Helio `releaseBundle`: six deployables plus `release-manifest.properties` and `SHA256SUMS`; bundle ZIP SHA-256 `4799733be6a178a7ed119d69f4945453dec1d73fbab7a22e95e51e259e035ded`; `product_version=0.0.1`; root JDK `21.0.10`, modern JDK `25.0.4.1`, Gradle `9.6.1`; all eight entries and the three-version compatibility contract were independently verified locally. | Candidate build is green; it is not a protected-main CI result and cannot be tagged until the GUI, federation, Vulcan, production provider freeze, and current-head CI gates close. |
| Helio repository static wrappers | Passed 14/14 | [`cluster-helio-static-suite-2026-08-22.json`](evidence/cluster-helio-static-suite-2026-08-22.json) records `HELIO_STATIC_ALL_PASS` on `helio` with Windows PowerShell 5.1 at source `50362a1`. | Cluster execution is verified; this does not close the external GUI, licensed Vulcan, or real federation gates. |
| Current-head regression suite | Passed 15/15 locally plus current-source Helio Gradle verification | [`static-regression-2026-08-24-473ef5b.json`](evidence/static-regression-2026-08-24-473ef5b.json) records all wrapper hashes for exact source `473ef5b…`; [`cluster-helio-473ef5b-gradle-test-2026-08-24.json`](evidence/cluster-helio-473ef5b-gradle-test-2026-08-24.json) records Helio `BUILD SUCCESSFUL`, 69 tasks, JDK 21.0.10. Push [`32652019710`](https://github.com/TypeThe0ry/MCAce/actions/runs/32652019710) and rerun [`32652017358`](https://github.com/TypeThe0ry/MCAce/actions/runs/32652017358) both passed after one Linux cancellation-test flake. GUI, Vulcan, federation, production topology, and protected-main release gates remain open. |
| Current HEAD Helio Paper test | Passed 37 tests (0 failures, 0 errors, 1 skip) | [`cluster-helio-cc91c63-paper-test-2026-08-23.json`](evidence/cluster-helio-cc91c63-paper-test-2026-08-23.json) records exact detached source `cc91c632…`, Helio `BUILD SUCCESSFUL`, 179.005 s, `c2_crash=false`, and result/log hashes. | This closes the current-head Paper module test witness only; it is not protected-main `releaseBundle` CI and does not close GUI, federation, Vulcan, or production-authority gates. |
| Current HEAD Helio static wrappers | Passed 15/15 | [`cluster-helio-cd3921c-static-2026-08-23.json`](evidence/cluster-helio-cd3921c-static-2026-08-23.json) records all 15 wrapper exit codes as zero on exact source `cd3921c…` under Windows PowerShell 5.1; it closes the prior `GetRelativePath`/`FromHexString` compatibility failure. | Static wrappers are green; visible human consent, real federation, licensed Vulcan runtime, and production authority topology remain separate gates. |
| Fabric packaging, all targets | Passed | 1.21.11 final remapped artifact; 26.1.2 and 26.2 final named artifacts; target-specific metadata, build IDs, CodeSource/hash contracts, and package tests passed. | Packaging support is current for exactly the three documented tuples. |
| Paper/Folia × Velocity/Bungee version process matrix | Passed 12/12 on Helio | [Evidence index](evidence/server-version-process-matrix-2026-08-25-f404971.json) plus the immutable report/binding/commit triplet under [`evidence/server-version-process-matrix/2026-08-24T21-33-47-1914356Z/`](evidence/server-version-process-matrix/2026-08-24T21-33-47-1914356Z/); exact source `f404971e6e9a9ac1d30e5cf4e2692750aa83f1b1`, 10 STABLE + 2 BETA, cleanup zero, source manifest `db15e970…` / 686 files. | Signed admission and shadow backend context are proven on all three versions while the peer remains live. Paper 26.2 build 116 is STABLE; Folia 26.2 build 6 remains the two-case BETA lane. A transient JVM startup crash on the first resumed attempt was recovered by the checkpointed `-Resume` run and is documented in the evidence index. Online-mode/public-network behavior is not claimed. Protected-main CI and the external GUI/federation/Vulcan gates remain open. |
| Fabric server-only platform startup | Passed for all three targets | `platform-load-smoke.ps1 -FabricTarget <target>` passed for 1.21.11, 26.1.2, and 26.2 after full Minecraft asset prewarm. | Assets and server startup are not blockers. They are not visible-client consent evidence. |
| Fabric explicit-file and frame consent | Pending six human clicks | Report schema 7 and binding `MCACE_FABRIC_GUI_EVIDENCE_BINDING_V5` are implemented, including the named runtime-artifact hash and exact `velocity_policy_minecraft_versions` / `velocity_policy_client_build_ids` bindings. The latest current-source 1.21.11 attempt reached `EXPLICIT_FILE_CONSENT_RENDERED` and timed out without a human click; see [`fabric-gui-consent-attempt-2026-08-22.json`](evidence/fabric-gui-consent-attempt-2026-08-22.json). | Three targets × two prompts = six human approvals. Automation must not click or synthesize them. |
| Client-origin enforcement guard | Passed current-source 24/24 | [`disposition-current-2026-08-21.json`](evidence/disposition-current-2026-08-21.json); 8/8 on each of 1.21.11, 26.1.2, and 26.2; Execute and ReportOnly both passed. | `CLIENT_REPORTED` LIMIT/QUARANTINE/DENY remained advisory and no high-impact route executed. This remains distinct from SERVER_CONFIRMED. |
| Trusted administrator disposition | Passed current-source 18/18 | [`disposition-current-2026-08-21.json`](evidence/disposition-current-2026-08-21.json); 6/6 on each of 1.21.11, 26.1.2, and 26.2; Execute and ReportOnly both passed; `UUID_CONTEXT_COMMITMENT_V3`. | Durable authorization preceded execution and DENY remained current-connection-only; the real Grim producer is recorded separately in [`anti-cheat-real-server-2026-08-22.json`](evidence/anti-cheat-real-server-2026-08-22.json). |
| Real server anti-cheat detection/interception | Passed for real 1.21.11 loopback server and repeated against the tested MCAce artifact | [`rerun-2026-08-23.json`](evidence/real-server-2026-08-23/rerun-2026-08-23.json) binds tested source `27bb101…` to a Helio repeat run with Leaf 1.21.11 + real GrimAC `2.3.74-155abaf`: 40 movement probes, `AimDuplicateLook`/`Simulation`/`TickTimer`, three `SERVER_CONFIRMED` `BEHAVIOR_HIGH_RISK` events and three loopback risk uploads. | Detection and interception/upload are proven twice. `MONITOR`/`NONE` is intentional; no automatic kick/ban is asserted. Vulcan, GUI/federation, and production topology gates remain separate. |
| Current exact-release candidate anti-cheat rerun | Passed for the Paper artifact reused by the e7f6f74 candidate | [`current-candidate-fe5f2d1.json`](evidence/real-server-2026-08-23/current-candidate-fe5f2d1.json) binds Paper artifact `9bb12776…`, Leaf `1.21.11-135`, and GrimAC `2.3.74-155abaf`: Node.js 22.23.2 connected, 40 probes completed, and three `SERVER_CONFIRMED` events were uploaded with HTTP 202. The runtime record is source-bound to `fe5f2d1…`; the e7f6f74 manifest contains the same Paper artifact SHA. | Detection/interception is green for the identical Paper bytes; `MONITOR`/`NONE` remains intentional. This does not close licensed Vulcan, GUI/federation, production topology, or current-head CI. |
| Federation | V2 GUI implementation/static contract passed; real handoff pending | [`federation-durable-audit-2026-08-13.json`](evidence/federation-durable-audit-2026-08-13.json) remains the historical raw-peer 4/4 record. The three-target V2 wrapper and both UI decisions exist; PowerShell 7 and Windows PowerShell 5 static tests pass. | Static tests and the older raw peer do not prove human GUI coverage. A human must approve source export, disconnect/direct-connect to the exact target, approve target import, and keep the target session alive through expiry. Current-source raw-process evidence is also separate and pending. |
| Vulcan | Historical preflight retained; current-source runtime pending | [`vulcan-licensed-api-preflight-2026-08-13.json`](evidence/vulcan-licensed-api-preflight-2026-08-13.json) is historical structural evidence only. | Current-source structural preflight, Paper enablement, and one genuine externally triggered Vulcan event all remain pending. MCAce neither downloads nor bundles the licensed artifact. |
| SERVER_CONFIRMED producer | Grim real-process path passed; production freeze pending | [`rerun-2026-08-23.json`](evidence/real-server-2026-08-23/rerun-2026-08-23.json) proves a repeat real Grim provider and real Paper process reached the MCAce `SERVER_CONFIRMED` channel three times from the tested source `27bb101…` plugin artifact. The default-disabled codec/registry/journal/coordinator foundation remains unit-tested. | Provider/profile/key/topology freeze and the genuine licensed Vulcan producer are still pending; loopback evidence is not a production Cloud claim. |

The Linux witness binds source manifest
`b74c22ff187a1fcfe4d8e1d6da5a202bde67d72061bcb3c2f205532d3857f8c3`
and exact-eight canonical manifest
`289a59e56c6605e2f5ba7af160a9c94da506978e3c5db6e5c4102b578ce2ada3`.
The five-skip Windows/Linux delta is confined to PostgreSQL integration cases
because the isolated Linux container has no external PostgreSQL service; the
skip boundary is record-only, not a failed gate.

The current local-build and matrix repository JSON files hash to
`ebbecbf1b322322f3ba78de89e00016e447ab2fca310a6889bbf9d9b1f086060`
and `f62c2c846203bd8d6d411246ddeaddaa8d62dc81abb1ca3b135e7eaae021ea63`,
respectively.
The external Linux witness hashes to
`de6d82fedace1c7b961ba9879b6e924df1bc8a1d085b851134194bac91d44b48`;
it is not copied repository evidence.

## Current local exact-eight bundle

The byte-identical August 20 A/D local bundle recorded in
[`local-build-2026-08-20.json`](evidence/local-build-2026-08-20.json) contains:

| Entry | Role |
| --- | --- |
| `mcace-client-fabric-1.21.11.jar` | Fabric 1.21.11 remapped client |
| `mcace-client-fabric-26.1.2.jar` | Fabric 26.1.2 named client |
| `mcace-client-fabric-26.2.jar` | Fabric 26.2 named client |
| `mcace-server-velocity.jar` | Velocity proxy plugin |
| `mcace-server-bungeecord.jar` | BungeeCord proxy plugin |
| `mcace-server-paper.jar` | Paper/Folia backend plugin |
| `release-manifest.properties` | release identity and artifact metadata |
| `SHA256SUMS` | authoritative six-JAR hashes |

Build the dirty-safe local verification set with exact Java homes:

```powershell
$env:JAVA_HOME = '<Temurin 21.0.7+6 home>'
.\gradlew.bat clean build localVerificationBundle `
  "-PmcaceModernJavaHome=<Temurin 25.0.3+9 home>" `
  --offline --dependency-verification=strict --rerun-tasks `
  --no-build-cache --no-configuration-cache --no-daemon `
  --no-parallel --max-workers=1 --console=plain
```

`localVerificationBundle` writes only to `build/local-verification-bundle/`.
`releaseBundle` writes to `build/release-bundle/`, requires a clean worktree and
an exact lowercase 40-hex HEAD via `-PmcaceSourceCommit`, and must be produced by
the exact-commit CI/release path.

## Authoritative process commands

The current three-version proxy/backend gate is:

```powershell
.\scripts\server-version-process-matrix.ps1 -Execute
.\scripts\server-version-process-matrix.ps1 -ReportOnly
```

It pins Velocity `3.5.1-615`, BungeeCord `2085`, Paper builds
`1.21.11-132` / `26.1.2-74` / `26.2-116`, and Folia builds
`1.21.11-14` / `26.1.2-8` / `26.2-6`. It verifies the runtime-assets and
prepared-tree manifests, current source and product JARs, JDK/Gradle identities,
12 raw process results, the sanitized report/binding/commit triplet, cleanup, and
the absence of retained forwarding/private-key material.

The earlier `platform-load-smoke.ps1` invocations without `-FabricTarget`,
`bungee-paper-load-smoke.ps1`, `folia-process-smoke.ps1`,
`proxy-admission-player-smoke.ps1`, and `proxy-folia-context-smoke.ps1` records
for Minecraft 1.21.1/1.21.4 are legacy/historical. They remain useful debugging
context but are not the three-version release gate.

## Remaining execution order

1. On an unlocked display-capable desktop, run
   `platform-load-smoke.ps1 -FabricTarget <target> -WithFabricEvidence` once for
   each target and complete the two visible consent decisions per run. Revalidate
   each schema-7/V5 pair with `-ReportOnly` and independently reviewed hashes.
2. Complete the separate real Fabric federation source-export and target-import
   visible handoff gate. Raw-peer evidence must not be promoted to GUI coverage.
3. Freeze the SERVER_CONFIRMED provider/profile/key/topology choices in
   [SERVER_CONFIRMED_AUTHORITY.md](SERVER_CONFIRMED_AUTHORITY.md), promote the
   real Grim path from loopback evidence to the chosen production topology, and
   keep the Paper/Folia plus Velocity/Bungee process gates green.
4. Rerun the licensed Vulcan structural preflight against current source, then
   pass isolated Paper enablement and one genuine externally triggered event.
5. Review, commit, and push. Retain a passing protected-branch GitHub Actions run
   and generate the clean exact-commit `releaseBundle` candidate.

## Release decision

The three Fabric targets, six deployables, strict local A/D build, post-fix
12-case server matrix, and current Linux network-none rehearsal are green within
their documented local boundaries. An unqualified release claim remains
premature until the six visible GUI decisions and real Fabric federation handoff
complete, current-source Vulcan gates and the genuine SERVER_CONFIRMED
producer/configuration freeze complete, and exact-commit CI plus the clean
exact-commit release bundle pass.
