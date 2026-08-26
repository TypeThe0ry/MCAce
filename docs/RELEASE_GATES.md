# MCAce release gates

Evidence inventory audited August 26, 2026. Commit
`5a7e423b5b7bc6c79ea5e1fd3182b82923312169` is a retained August 25 feature-CI
snapshot, not the live repository HEAD and not a release identity. Authoritative
release status is recomputed from the checkout by `scripts/release-readiness.ps1`
and must be confirmed again by protected `MCACE_RELEASE_BUNDLE_V4` CI.
Files below `build/` are mutable diagnostics.
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
`release-manifest.properties`, and `SHA256SUMS`. Release manifests use
`MCACE_RELEASE_BUNDLE_V4`: `source_commit` is the protected final release HEAD,
while `artifact_source_commit` identifies the immutable source that produced all
six JARs. The tracked selector `docs/evidence/release-artifact-source.txt` must
be exactly one lowercase 40-hex commit plus LF, with no BOM, and must equal
the manifest artifact commit plus the selected Federation and server-matrix
artifact-source commits. The August 20 strict-offline records use
JDK `21.0.7+6` and isolated modern JDK `25.0.3+9`; the retained August 25 Helio
feature candidate used JDK `21.0.10` and modern JDK `25.0.4.1`. Both paths use
Gradle `9.6.1`. Root verification metadata contains 47 exact Loom-local trust entries
and `fabric-modern` contains two exact named-Minecraft trust entries. There is no
group-wide trust. The superseded 52-rule, exact-six, four-JAR Linux rehearsal is
historical only and cannot be promoted to the `v0.0.1` three-version release.
The protected final release HEAD may differ from the artifact source only by
`README.md`, `README_CN.md`, and tracked files below `docs/evidence/`; code,
workflow, build-script, or other documentation changes require a new artifact
source and rebuilt evidence.

Externally supervised Matrix, Federation, and Production Authority capture
packages are created at artifact commit **A**. Their stored release/capture bundle
therefore has `source_commit=A`, `artifact_source_commit=A`, and a manifest hash
for A. Publishing those tracked evidence files creates the protected descendant
release commit **R**. Protected CI rebuilds the final bundle with
`source_commit=R` and `artifact_source_commit=A`, proves that `A..R` contains only
the allowlisted evidence/README delta, and requires `SHA256SUMS` plus every
deployable JAR to remain byte-identical to the externally signed A artifact set.
The A and R manifest hashes are intentionally different because the embedded
`source_commit` differs; requiring a tracked evidence file to contain R's own
commit or final-manifest hash would create an impossible Git self-reference.

## Gate matrix

| Gate | State | Evidence / required proof | Release interpretation |
| --- | --- | --- | --- |
| Strict offline Windows reproducibility | Passed locally | [`local-build-2026-08-20.json`](evidence/local-build-2026-08-20.json); independent clean August 20 A/D runs each completed 118/118 tasks. Root: 147 suites / 681 tests / 0 failures / 0 errors / 28 skipped. Modern: 24 / 74 / 0 / 0 / 0. Combined: 171 / 755 / 0 / 0 / 28. Exact-eight A/D bytes match. | Strong sanitized local reproducibility evidence. The manifest is `LOCAL_VERIFICATION`, `release_identity=false`, and `source_commit=LOCAL_UNSPECIFIED`; it is not a release candidate. |
| Linux network-none rehearsal | Passed for the retained local boundary | [`local-build-2026-08-20.json`](evidence/local-build-2026-08-20.json), run `cb6dc44ddad744b5a20dc2986c0a6d70`; strict offline network-none; exact JDK 21.0.7+6/JDK 25.0.3+9; 118 root actionable tasks plus 15/15 modern tasks; 171 suites / 755 tests / 0 failures / 0 errors / 33 environment-conditioned skips; unchanged 735-file source manifest; all eight entries stream-byte-identical to Windows A/D; cleanup zero at 0/30/60 seconds. | The retained Linux witness proves parity only for that LOCAL exact-eight boundary. Its detailed raw witness remains external and the repository record is sanitized; it is not exact-commit release identity. |
| GitHub Actions / exact commit | Historical feature CI passed for `5a7e423b5b7bc6c79ea5e1fd3182b82923312169`; **PENDING — protected V4 `main` and tag CI** | [Push run `32803002956`](https://github.com/TypeThe0ry/MCAce/actions/runs/32803002956) and [PR run `32803006026`](https://github.com/TypeThe0ry/MCAce/actions/runs/32803006026), with sanitized [evidence](evidence/github-feature-ci-2026-08-25-5a7e423.json), passed exact checkout, build/test, local-verification bundle, and exact-eight upload. `releaseBundle` and readiness are deliberately restricted to protected `main` and `v0.0.1` tag refs. | The historical feature witness is green but cannot close release CI. Merge to protected `main` only after external gates close, verify the exact V4 bundle/readiness there, then rerun the same exact-commit path on the `v0.0.1` tag before publishing. |
| Fail-closed readiness | **PENDING — Matrix V4, Federation V5, Vulcan V3, Authority V4, and protected V4 CI** | [`release-readiness-2026-08-25-5a7e423.json`](evidence/release-readiness-2026-08-25-5a7e423.json) is a historical feature evaluation only. The validator now requires the Matrix V4 raw twelve-case set and external supervisor receipt, the Federation V5 eight-file set and two independently approved signer pins, externally signed Vulcan V3 genuine-event evidence, externally signed Authority V4 raw evidence, the canonical artifact-source marker, `MCACE_RELEASE_BUNDLE_V4`, and Fabric compatibility report V2. It validates `build/release-bundle` only in protected `main` or `v0.0.1` tag push CI context. | No caller Boolean or historical document can promote a gate. Rerun `scripts/release-readiness.ps1` after every evidence or exact-source change; Matrix V1/V2/V3, Federation V4, Vulcan V2, and Authority V1/V3 records remain diagnostic only. |
| GitHub branch/tag protection | Policy configured; **PENDING — protected V4 release execution** | [`github-protection-2026-08-25.json`](evidence/github-protection-2026-08-25.json) records strict `main` protection with required `build`, operator-only `v0.0.1` tag creation, and active tag deletion/update rules with `current_user_can_bypass=never`. | Repository policy is configured; the protected `main`/`v0.0.1` exact-commit V4 CI still has to run after the external gates close. |
| Historical recorded exact-commit CI / release bundle | Passed for merged source `f355a85f65173c6e98ab685e3b36f5e172b85498` | Run [`32570987482`](https://github.com/TypeThe0ry/MCAce/actions/runs/32570987482) verified that checkout, ran build/test, built its exact candidate, uploaded all eight entries, and passed local SHA256 verification. See [`release-bundle-2026-08-22-f355a85.json`](evidence/release-bundle-2026-08-22-f355a85.json). | Historical exact-source evidence only. The eventual release commit must receive its own required protected `build` check. |
| Historical Helio exact-commit feature candidate | Passed for feature source `63ae400adc8d09d8349ca599c9d6a4866a189d04` | [`release-bundle-2026-08-25-63ae400.json`](evidence/release-bundle-2026-08-25-63ae400.json) records Helio `releaseBundle`: six deployables plus `release-manifest.properties` and `SHA256SUMS`; remote artifact hashes, `product_version=0.0.1`, root JDK `21.0.10`, modern JDK `25.0.4.1`, Gradle `9.6.1`, and the three-version compatibility contract all passed. | Retained feature-source evidence only. It is not protected-main CI and cannot be tagged until the named external gates and protected V4 CI close. |
| Historical Helio exact-commit release candidate | Passed for immutable source `e7f6f74a9d08b6c4cef829b7b5e65ba150f5d834` | [`release-bundle-e7f6f74.json`](evidence/release-bundle-e7f6f74.json) records the retained historical candidate and its independent eight-entry verification. | Historical evidence only. |
| Helio repository static wrappers | Passed 14/14 | [`cluster-helio-static-suite-2026-08-22.json`](evidence/cluster-helio-static-suite-2026-08-22.json) records `HELIO_STATIC_ALL_PASS` on `helio` with Windows PowerShell 5.1 at source `50362a1`. | Cluster execution is verified; this does not close the external GUI, licensed Vulcan, or real federation gates. |
| Retained exact-source regression suite | Passed 15/15 locally plus Helio Gradle verification for `473ef5b…` | [`static-regression-2026-08-24-473ef5b.json`](evidence/static-regression-2026-08-24-473ef5b.json) records all wrapper hashes for exact source `473ef5b…`; [`cluster-helio-473ef5b-gradle-test-2026-08-24.json`](evidence/cluster-helio-473ef5b-gradle-test-2026-08-24.json) records Helio `BUILD SUCCESSFUL`, 69 tasks, JDK 21.0.10. Push [`32652019710`](https://github.com/TypeThe0ry/MCAce/actions/runs/32652019710) and rerun [`32652017358`](https://github.com/TypeThe0ry/MCAce/actions/runs/32652017358) both passed after one Linux cancellation-test flake. | Historical exact-source regression evidence; it does not close any external gate or protected V4 CI. |
| Retained Helio Paper module test | Passed 37 tests (0 failures, 0 errors, 1 skip) for `cc91c632…` | [`cluster-helio-cc91c63-paper-test-2026-08-23.json`](evidence/cluster-helio-cc91c63-paper-test-2026-08-23.json) records exact detached source `cc91c632…`, Helio `BUILD SUCCESSFUL`, 179.005 s, `c2_crash=false`, and result/log hashes. | Historical module evidence only; it is not protected V4 bundle CI and does not close GUI, Federation V5, Vulcan V3, or Authority V4. |
| Retained Helio static wrappers | Passed 15/15 for `cd3921c…` | [`cluster-helio-cd3921c-static-2026-08-23.json`](evidence/cluster-helio-cd3921c-static-2026-08-23.json) records all 15 wrapper exit codes as zero under Windows PowerShell 5.1; it closed the prior `GetRelativePath`/`FromHexString` compatibility failure for that source. | Historical wrapper evidence only; the external and protected release gates remain separate. |
| Fabric packaging, all targets | Passed | 1.21.11 final remapped artifact; 26.1.2 and 26.2 final named artifacts; target-specific metadata, build IDs, CodeSource/hash contracts, and package tests passed. | Packaging support is implemented for exactly the three documented tuples. |
| Paper/Folia × Velocity/Bungee version process matrix | **PENDING — Matrix V4 external-supervisor evidence**; historical Matrix V1 12/12 is diagnostic only | The [historical V1 index](evidence/server-version-process-matrix-2026-08-25-f404971.json) and V1 triplet under [`evidence/server-version-process-matrix/2026-08-24T21-33-47-1914356Z/`](evidence/server-version-process-matrix/2026-08-24T21-33-47-1914356Z/) record exact source `f404971e6e9a9ac1d30e5cf4e2692750aa83f1b1`, 12/12, 10 STABLE + 2 BETA, cleanup zero, and source manifest `db15e970…` / 686 files. They do not contain the twelve immutable raw case reports, raw manifest, protected bundle binding, or independent supervisor receipt required by V4. V2 and V3 are terminally release-ineligible. | [Matrix V4](SERVER_VERSION_MATRIX_EVIDENCE_V4.md) is the first release-capable contract. It revalidates exactly twelve raw reports, case/process incarnations and exit/cleanup, ordered raw hashes, source/artifact commits, all six release JARs, the three server JARs, an exact protected V4 bundle, and an externally signed receipt that the producer/publisher accepted inside its short exchange window under an out-of-band approved pin. Later readiness verifies the immutable historical ordering/signature rather than expiring it by current wall clock. No release-eligible V4 index is retained. Paper 26.2 build 116 is STABLE; Folia 26.2 build 6 remains the two-case BETA lane. Online-mode/public-network behavior is not claimed. |
| Fabric server-only platform startup | Passed for all three targets | `platform-load-smoke.ps1 -FabricTarget <target>` passed for 1.21.11, 26.1.2, and 26.2 after full Minecraft asset prewarm. | Assets and server startup are not blockers. They are not visible-client consent evidence. |
| Fabric MCAce enablement consent | **PENDING — exactly one connection-bound visible `Enable MCAce` confirmation for the entire release acceptance** | One selected real connection must render one visible screen and record one human approval. That same decision is consumed by the Federation V5 handoff. `MCACE_VISIBLE_GUI_ATTESTATION_V3` is signed by the approved GUI key; after runtime, a distinct approved supervisor key signs `MCACE_FABRIC_FEDERATION_POSTRUN_RECEIPT_V1`. The other two Fabric versions receive UI compatibility/visual smoke only: they are not extra approvals and cannot mint or promote release consent. | This is one release-acceptance witness, not three or six clicks and not reusable consent for later connections. Close, decline, timeout, missing/invalid receipt, headless/synthetic input, fixture/self-approved keys, equal pins, or byte mutation leaves MCAce disabled and the gate pending. The post-run signature adds no UI. |
| Client-origin enforcement guard | Passed in the retained August 21 record, 24/24 | [`disposition-current-2026-08-21.json`](evidence/disposition-current-2026-08-21.json); 8/8 on each of 1.21.11, 26.1.2, and 26.2; Execute and ReportOnly both passed. | `CLIENT_REPORTED` LIMIT/QUARANTINE/DENY remained advisory and no high-impact route executed. This remains distinct from SERVER_CONFIRMED. |
| Trusted administrator disposition | Passed in the retained August 21 record, 18/18 | [`disposition-current-2026-08-21.json`](evidence/disposition-current-2026-08-21.json); 6/6 on each of 1.21.11, 26.1.2, and 26.2; Execute and ReportOnly both passed; `UUID_CONTEXT_COMMITMENT_V3`. | Durable authorization preceded execution and DENY remained connection-local; the real Grim producer is recorded separately in [`anti-cheat-real-server-2026-08-22.json`](evidence/anti-cheat-real-server-2026-08-22.json). |
| Real server anti-cheat detection/interception | Passed for real 1.21.11 loopback server and repeated against the tested MCAce artifact | [`rerun-2026-08-23.json`](evidence/real-server-2026-08-23/rerun-2026-08-23.json) binds tested source `27bb101…` to a Helio repeat run with Leaf 1.21.11 + real GrimAC `2.3.74-155abaf`: 40 movement probes, `AimDuplicateLook`/`Simulation`/`TickTimer`, three `SERVER_CONFIRMED` `BEHAVIOR_HIGH_RISK` events and three loopback risk uploads. | Detection and interception/upload are proven twice. `MONITOR`/`NONE` is intentional; no automatic kick/ban is asserted. Vulcan, GUI/federation, and production topology gates remain separate. |
| Historical exact-candidate anti-cheat rerun | Passed for the Paper bytes later reused by the `e7f6f74…` candidate | [`current-candidate-fe5f2d1.json`](evidence/real-server-2026-08-23/current-candidate-fe5f2d1.json) binds Paper artifact `9bb12776…`, Leaf `1.21.11-135`, and GrimAC `2.3.74-155abaf`: Node.js 22.23.2 connected, 40 probes completed, and three `SERVER_CONFIRMED` events were uploaded with HTTP 202. The runtime record is source-bound to `fe5f2d1…`; the `e7f6f74…` manifest contains the same Paper artifact SHA. | Retained detection/interception evidence for identical Paper bytes; `MONITOR`/`NONE` remains intentional. It does not close Vulcan V3, GUI/Federation V5, Authority V4, or protected V4 CI. |
| Federation | **PENDING — Federation V5 externally signed handoff evidence** | [`federation-durable-audit-2026-08-13.json`](evidence/federation-durable-audit-2026-08-13.json) remains historical raw-peer context only. The V5 native set is exactly eight regular files: report, binding, commit, runner-generated `MCACE_VISIBLE_GUI_SIGNING_REQUEST_V1`, signed GUI attestation, PNG, runtime ledger, and externally signed post-run receipt. The retained request is hash-bound by the V3 attestation and revalidated against report/binding/path/artifact/session fields. The post-run signature covers source/artifact commits, product/route, manifest and exact Fabric/Paper/source-proxy/target-proxy hashes, both challenges/attempt, all critical process incarnations, GUI and decoded-pixel hashes, ledger raw hash/head/seal/count, and immutable report/binding raw hashes. Commit/index then bind the receipt without creating a signature cycle. | Real execution still requires the one release-acceptance approval, direct source-to-target transition with no second prompt, live-through-expiry observation, two exact correlated negatives, zero residue, and two externally held private keys. The protected workflow must supply two distinct approved pins; V4, fixture, equal-key, missing-receipt, and tampered sets fail closed. No production V5 receipt is retained. |
| Vulcan | **PENDING — externally pinned supervisor-signed Vulcan V3 genuine-event evidence** | [`vulcan-licensed-api-preflight-2026-08-13.json`](evidence/vulcan-licensed-api-preflight-2026-08-13.json) is historical structural evidence. V3 is implemented as an exact seven-file package: raw risk event, append-only callback-provenance ledger, report, binding, canonical signing request, external supervisor receipt, and commit. The callback ledger proves Bukkit handler/plugin/event/code-source/accessor/thread/process identity without a compile-time licensed dependency; the receipt binds those bytes plus exact Vulcan, upstream Paper, and MCAce Paper hashes. Producer files remain `release_eligible=false`. | The publisher terminally rejects V2 with `MCACE_NATIVE_EVIDENCE_VULCAN_V2_DIAGNOSTIC_NOT_RELEASE_GRADE`. No non-fixture licensed V3 event/receipt is retained. Producer and publisher require the receipt to be current; later protected readiness revalidates the immutable signed acceptance window rather than expiring it by wall clock. MCAce neither downloads nor bundles the licensed Vulcan artifact and does not claim kernel, DMA, or Tencent ACE parity. |
| SERVER_CONFIRMED production authority | **PENDING — Authority V4 genuine external raw capture and receipt/index** | The V4 contract consumes actual proxy-signed grant and backend-signed observation protobuf bytes, recomputes signing inputs/CRC32C/grant and provider commitments, verifies the raw provider/Paper/proxy chain plus journal/process cleanup, binds the exact V4 release Paper/Velocity/Bungee JARs, and verifies an externally pinned Ed25519 supervisor receipt. The prepublication package is 14 canonical root documents plus the exact ten artifact bytes named by its manifest; producer report/binding/commit remain `release_eligible=false`. | No externally operated supervisor receipt, production-topology capture, or licensed genuine Vulcan event is retained. Only `publish-native-release-evidence.ps1` may emit `MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V4` with `release_eligible=true` after staged raw revalidation and one-time challenge/attempt replay checks. V1/V3 summaries, caller booleans, fixture/self-approved keys, missing raw frames, bad signatures, fake JARs, and reparse/replacement inputs fail closed. |

The Linux witness binds source manifest
`b74c22ff187a1fcfe4d8e1d6da5a202bde67d72061bcb3c2f205532d3857f8c3`
and exact-eight canonical manifest
`289a59e56c6605e2f5ba7af160a9c94da506978e3c5db6e5c4102b578ce2ada3`.
The five-skip Windows/Linux delta is confined to PostgreSQL integration cases
because the isolated Linux container has no external PostgreSQL service; the
skip boundary is record-only, not a failed gate.

The retained August 20 local-build record and historical Matrix V1 index hash to
`ebbecbf1b322322f3ba78de89e00016e447ab2fca310a6889bbf9d9b1f086060`
and `5ea6f977c1fa8c9019deab8aaafa14f234745a4595db1ec026be0a3cfc1beac5`,
respectively.

The source workspace is maintained under `<workspace>\MCAce`. The original
`%USERPROFILE%\MCAce` tree was removed only after exact file/byte and RoboCopy
dry-run verification; the migration manifest and logs are recorded in
[`PROJECT_MIGRATION.md`](PROJECT_MIGRATION.md).
The external Linux witness hashes to
`de6d82fedace1c7b961ba9879b6e924df1bc8a1d085b851134194bac91d44b48`;
it is not copied repository evidence.

## Historical local exact-eight bundle witness

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
an exact lowercase 40-hex protected HEAD via `-PmcaceSourceCommit`, and must be
produced by the exact-commit CI/release path. Its V4 manifest also records the
selected artifact commit. The V2 compatibility report repeats both commits and
re-hashes the three final Fabric JARs. Readiness accepts the bundle only when the
protected CI environment, HEAD, manifest final commit, canonical tracked marker,
compatibility report, federation source commit, per-target Fabric build IDs, and
all six JAR hashes agree.

## Authoritative Matrix V4 process commands

[Matrix V4](SERVER_VERSION_MATRIX_EVIDENCE_V4.md) is the first release-capable
server-matrix workflow. The protected release process supplies an independently
approved trust-root pin; the caller must not derive approval merely from the file
it is about to validate. A minimal external-supervisor run is:

```powershell
$artifactCommit = (Get-Content -Raw docs\evidence\release-artifact-source.txt).Trim()
$bundle = (Resolve-Path build\release-bundle).Path
$trustRoot = 'C:\MCAceReleaseAuthority\matrix-supervisor-public.json'
$exchange = 'C:\MCAceReleaseAuthority\matrix-exchange'
$pin = $env:MCACE_RELEASE_APPROVED_MATRIX_SUPERVISOR_TRUST_ROOT_SHA256

if ((Get-FileHash -LiteralPath $trustRoot -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pin) {
  throw 'MATRIX_SUPERVISOR_TRUST_ROOT_PIN_MISMATCH'
}
$env:MCACE_ARTIFACT_SOURCE_COMMIT = $artifactCommit
$env:MCACE_MATRIX_RELEASE_BUNDLE_ROOT = $bundle
$env:MCACE_MATRIX_SUPERVISOR_TRUST_ROOT_PATH = $trustRoot
$env:MCACE_MATRIX_SUPERVISOR_EXCHANGE_ROOT = $exchange

.\scripts\server-version-process-matrix.ps1 -Execute `
  -ExpectedSourceCommit $artifactCommit -ReleaseBundleRoot $bundle `
  -SupervisorTrustRootPath $trustRoot `
  -ExpectedSupervisorTrustRootSha256 $pin `
  -SupervisorExchangeRoot $exchange -SupervisorReceiptWaitSeconds 300

# A separately controlled supervisor verifies the printed request and atomically
# writes the detached receipt to the printed receipt path; no private key enters
# this repository or command line.

.\scripts\server-version-process-matrix.ps1 -ReportOnly `
  -ExpectedSourceCommit $artifactCommit -ReleaseBundleRoot $bundle `
  -SupervisorTrustRootPath $trustRoot `
  -ExpectedSupervisorTrustRootSha256 $pin

$run = Get-ChildItem build\server-version-process-matrix\runs -Directory |
  Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
.\scripts\publish-server-version-matrix-evidence.ps1 `
  -ReportPath (Join-Path $run.FullName 'report.json') `
  -BindingPath (Join-Path $run.FullName 'binding.json') `
  -CommitPath (Join-Path $run.FullName 'commit.json') `
  -ReleaseBundleRoot $bundle -ArtifactSourceCommit $artifactCommit `
  -SupervisorTrustRootPath $trustRoot `
  -ExpectedSupervisorTrustRootSha256 $pin
```

The pinned asset set remains Velocity `3.5.1-615`, BungeeCord `2085`, Paper
`1.21.11-132` / `26.1.2-74` / `26.2-116`, and Folia `1.21.11-14` /
`26.1.2-8` / `26.2-6`. V4 executes all twelve cases and freezes exactly twelve
raw reports plus `raw-manifest.json`, report, binding, signing request, detached
receipt, and commit. Producer, publisher, and readiness each revalidate raw bytes,
case IDs, process incarnations/exits/cleanup, ordered roots, exact source/artifact
commits, the protected V4 bundle, and the Velocity/Bungee/Paper JARs. V1/V2/V3
are rejected as release evidence. No independently signed V4 package is retained,
so this gate is **PENDING**.

The earlier `platform-load-smoke.ps1` invocations without `-FabricTarget`,
`bungee-paper-load-smoke.ps1`, `folia-process-smoke.ps1`,
`proxy-admission-player-smoke.ps1`, and `proxy-folia-context-smoke.ps1` records
for Minecraft 1.21.1/1.21.4 are legacy/historical. They remain useful debugging
context but are not the three-version release gate.

## Remaining execution order

1. Provision two external RSA public-key trust roots outside the repository: one
   for the visible-GUI signer and one for the post-run supervisor. Their paths,
   key IDs, public keys, and SHA-256 pins must differ. Protected CI or the external
   release policy must inject the approved lowercase pins independently as
   `MCACE_RELEASE_APPROVED_FEDERATION_GUI_TRUST_ROOT_SHA256` and
   `MCACE_RELEASE_APPROVED_FEDERATION_POSTRUN_TRUST_ROOT_SHA256`; command-line
   `-Expected*Sha256` values are assertions, not authorization. Neither private key
   is generated, copied, logged, or stored in this repository.
2. On one unlocked display-capable desktop, run
   `fabric-federation-gui-handoff-smoke.ps1 -Execute` for one representative target,
   supplying initially nonexistent absolute output paths through
   `-VisibleGuiSigningRequestPath`, `-VisibleGuiAttestationPath`, and
   `-VisibleGuiScreenshotPath`, plus
   `-VisibleGuiTrustRootPath`, `-ExpectedVisibleGuiTrustRootSha256`,
   `-PostRunSupervisorTrustRootPath`, `-ExpectedPostRunSupervisorTrustRootSha256`,
   `-PostRunSigningRequestPath`, `-PostRunReceiptPath`, and the exact
   `-ReleaseBundleRoot`. During the real prompt/accept window, ComputerUse captures
   the PNG; the runner atomically emits `MCACE_VISIBLE_GUI_SIGNING_REQUEST_V1`, and
   the independent signer produces `MCACE_VISIBLE_GUI_ATTESTATION_V3` over that
   request hash, the random challenge, and all bound process/session/artifact fields. The
   receipt, key, and screenshot must pass signature, time-window, no-follow identity,
   full PNG decode, independent approved-pin, and exact V4 bundle checks.
3. Complete that same one-confirmation real source-to-target handoff: source export
   consumes the decision, target import stays provisional and opens no second prompt,
   and promotion occurs only after presentation commit. The GUI signing request is
   retained with the attestation as one of eight durable files. After both real negative
   requests and cleanup, the runner writes immutable report/binding and creates the
   separate post-run external signing request. The distinct supervisor signs that V1 payload and
   atomically creates `-PostRunReceiptPath`; only then may the runner write commit.
   Revalidate the eight-file V5 set with `-ReportOnly`, then publish it with
   `publish-native-release-evidence.ps1 -Gate Federation` using both trust-root paths,
   both expected pins, and the exact release bundle. Run `release-readiness.ps1` with
   the same two root/path pairs and protected approved-pin environment. Fixture
   roots/receipts, raw-peer evidence, report booleans, V4 indexes/documents, or
   platform-only GUI evidence cannot be promoted to release coverage.
4. Execute the Matrix V4 workflow above on the exact artifact source and protected
   V4 bundle. The external Matrix supervisor must validate the twelve real process
   cases and atomically return the unexpired detached receipt under the out-of-band
   approved root pin. Publish the complete V4 package (including all twelve raw
   reports) and rerun its `-ReportOnly` validation. The retained 12/12 V1 aggregate
   and every V2/V3 document remain diagnostic and cannot substitute for this step.
5. Freeze the SERVER_CONFIRMED provider/profile/key/topology choices with
   Production Authority V4 evidence with `provision-production-authority.ps1`
   (freeze-manifest v3 and issuance-journal v3 component formats) using an external supervisor public
   descriptor and out-of-band approved descriptor SHA-256. Promote the real Grim
   path from loopback evidence to the chosen production topology, load the reviewed
   licensed Vulcan JAR, and capture actual signed grant/observation frames plus raw
   provider/Paper/proxy/process/journal ledgers. Have the external supervisor sign
   the V4 receipt payload, then run `production-authority-process-evidence.ps1` and
   publish with `publish-native-release-evidence.ps1 -Gate ProductionAuthority`
   against the exact V4 release bundle. The publisher must emit a new one-time
   `MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V4`; fixture outputs and the
   producer's `release_eligible=false` 14-document/ten-artifact package do not
   close the gate. Readiness repeats the raw-frame/signature/commitment validator,
   requires the out-of-band approved descriptor pin and pinned OpenSSL executable,
   cross-checks the protected V4 Paper/Velocity/Bungee JARs, and rejects reused
   challenge or attempt IDs. See
   [SERVER_CONFIRMED_AUTHORITY.md](SERVER_CONFIRMED_AUTHORITY.md) and
   [PRODUCTION_AUTHORITY_PROVISIONING.md](PRODUCTION_AUTHORITY_PROVISIONING.md).
6. Retain the licensed Vulcan V2 report/binding/commit only as diagnostic evidence.
   Execute the V3 runner with the reviewed licensed Vulcan JAR, upstream Paper, exact
   release `mcace-server-paper.jar`, an out-of-band exchange, and an independently
   approved Vulcan supervisor root. V3 retains the raw risk event, the MCAce
   append-only genuine-callback provenance ledger, report/binding, canonical signing
   request, external receipt, and commit. Publish that exact seven-file package only
   while the receipt is current. Protected readiness later verifies the immutable
   signature, A/R artifact equality, acceptance-window ordering, replay uniqueness,
   and hash chain without treating the short exchange TTL as permanent evidence
   expiry. Until a non-fixture V3 package and index are retained, the gate stays false.
7. Review, commit, and push the artifact source, then write its commit to the tracked
   canonical `docs/evidence/release-artifact-source.txt`. Retain a passing protected-
   branch GitHub Actions run whose V4 manifest final commit is the protected HEAD and
   whose artifact commit equals that marker, the Federation V5 evidence, and the
   Matrix V4 evidence. Generate and verify the exact-eight bundle, publish the full
   native Matrix V4 package with its twelve raw reports, supervisor receipt, and
   three server-JAR cross-bindings, and rerun readiness before any tag or release
   action. Protected V4 `main`/tag CI remains **PENDING** until that run succeeds.

## Release decision

The three Fabric targets, six deployables, strict August 20 local A/D build, the
historical 12/12 Matrix V1 diagnostic, and the retained Linux network-none witness
are green only within their documented historical/local boundaries. They do not
close release readiness. The release remains **PENDING** until exactly one signed,
visible, connection-bound `Enable MCAce` acceptance and the real Federation V5
handoff complete; Matrix V4, Vulcan V3, and Authority V4 each have genuine external
supervisor evidence; and protected exact-commit V4 `main`/tag CI passes with the
canonical artifact-source marker and exact bundle.
