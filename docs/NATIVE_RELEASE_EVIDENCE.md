# Native release evidence publishing

`scripts/publish-native-release-evidence.ps1` is the only promotion step for the
native release gates. It copies the already completed native bytes without
normalizing them and writes a small tracked index whose descriptors bind the
canonical repository-relative path, SHA-256, and byte count of every retained
file. Producer reports remain `release_eligible=false`; only a successful
publisher revalidation may create a release-eligible index.

## Supported gates

| `-Gate` | Exact native input | Release index |
| --- | --- | --- |
| `Federation` | Eight regular files: `report.json`, `binding.json`, `commit.json`, `visible-gui-signing-request.json`, `visible-gui-attestation.json`, `visible-gui.png`, `runtime-events.jsonl`, `post-run-receipt.json` | `MCACE_FABRIC_FEDERATION_GUI_HANDOFF_EVIDENCE_INDEX_V5` |
| `Vulcan` | V3: seven regular files: `report.json`, `binding.json`, `commit.json`, `signing-request.json`, `supervisor-receipt.json`, `raw-risk-event.json`, `callback-provenance.jsonl` | `MCACE_VULCAN_GENUINE_EVENT_EVIDENCE_INDEX_V3` |
| `ProductionAuthority` | V4 fourteen-document root plus the exact ten artifacts named by its manifest | `MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V4` |

Vulcan V2 remains a three-file diagnostic input and is terminally rejected with
`MCACE_NATIVE_EVIDENCE_VULCAN_V2_DIAGNOSTIC_NOT_RELEASE_GRADE`. Federation V4,
Authority V1/V3, fixtures, caller assertions, and manually authored summaries
cannot be promoted.

## Federation V5

The visible GUI signer receives the runner-generated
`MCACE_VISIBLE_GUI_SIGNING_REQUEST_V1`. The signed
`MCACE_VISIBLE_GUI_ATTESTATION_V3` commits that request SHA-256, the frozen PNG,
one run attempt, one GUI attempt, one challenge, one client process incarnation,
the exact artifact commit, route, and Fabric JAR. Exactly one acceptance is
permitted. The signing request is retained as the eighth durable native file;
report, binding, attestation, runtime ledger, post-run receipt, commit, and index
all re-establish the chain.

The release index also exposes the signed GUI attempt/challenge and post-run
operation/challenge. Publication holds a repository-wide cross-process mutex from
the sibling replay scan through atomic installation; `-Force` cannot reuse any of
those four values. Protected readiness independently scans every sibling V5 index,
so duplicated packages remain fail closed even after publication.

```powershell
$env:MCACE_RELEASE_APPROVED_FEDERATION_GUI_TRUST_ROOT_SHA256 = '<approved-gui-pin>'
$env:MCACE_RELEASE_APPROVED_FEDERATION_POSTRUN_TRUST_ROOT_SHA256 = '<approved-postrun-pin>'

pwsh -NoProfile -File scripts/publish-native-release-evidence.ps1 `
  -Gate Federation `
  -ReportPath D:\evidence\federation\report.json `
  -BindingPath D:\evidence\federation\binding.json `
  -CommitPath D:\evidence\federation\commit.json `
  -SourceCommit (git rev-parse HEAD) `
  -VisibleGuiTrustRootPath D:\release-roots\federation-gui.json `
  -ExpectedVisibleGuiTrustRootSha256 '<approved-gui-pin>' `
  -PostRunSupervisorTrustRootPath D:\release-roots\federation-postrun.json `
  -ExpectedPostRunSupervisorTrustRootSha256 '<approved-postrun-pin>' `
  -ReleaseBundleRoot build\release-bundle
```

Both roots are out-of-band, approved independently, and must differ. The private
keys, exchange directories, and transient signer state stay outside the repository.

## Vulcan V3 genuine-event gate

V3 consumes the reviewed licensed Vulcan JAR and exact upstream Paper plus the
release MCAce Paper JAR. MCAce neither downloads nor publishes the licensed JAR.
The Paper adapter has no compile-time Vulcan dependency; it registers through the
runtime API and writes an append-only callback provenance record only from the
actual Bukkit callback.

The provenance record binds the Vulcan plugin instance identity, plugin name,
version, main class and code-source hash; MCAce owner/listener identity; registered
handler and runtime event classes and their code sources; accessor declaring
methods and code sources; callback thread/time/sequence; player, provider-event,
check and violation commitments; Paper PID/start/incarnation; and the V3
attempt/challenge. A PowerShell Boolean or a locally fabricated risk body is not an
event-origin proof.

The runner writes `MCACE_VULCAN_GENUINE_EVENT_SIGNING_REQUEST_V1` to a repository-
external exchange and accepts only an independently signed
`MCACE_VULCAN_GENUINE_EVENT_SUPERVISOR_RECEIPT_V1` under the approved pinned root.
The receipt covers artifact hashes, raw event and callback ledger bytes, report and
binding bytes, process identity, challenge, attempt and time window. The producer
package stays `release_eligible=false` and `fixture=false`.

```powershell
$env:MCACE_VULCAN_SUPERVISOR_TRUST_ROOT_SHA256 = '<approved-vulcan-pin>'

pwsh -NoProfile -File scripts/vulcan-genuine-event-smoke.ps1 `
  -Execute -ReleaseGradeV3 -AllowTemporaryPaperRemap `
  -SourceCommit '<frozen-40-hex-source-A>' -ProductVersion '0.0.1' `
  -VulcanJar D:\licensed\Vulcan.jar `
  -VulcanSha256 7ee3a4fdd7e9da5269f9efc327478e507563e6e7df7abec2222acd3b499bc993 `
  -PaperJar D:\reviewed\paper.jar -PaperSha256 '<paper-sha256>' `
  -MCAceJar build\release-bundle\mcace-server-paper.jar -MCAceSha256 '<mcace-paper-sha256>' `
  -PreparedRoot D:\prepared\paper -PreparedManifestSha256 '<prepared-manifest-sha256>' `
  -ExpectedPlayerUuid '<dedicated-test-player-uuid>' `
  -PaperListenPort 25565 -NetworkPolicy DenyAll `
  -NetworkIsolationAttested -GenuineExternalTriggerAttested `
  -NoSyntheticEventInjectionAttested `
  -SupervisorExchangeRoot D:\vulcan-exchange\attempt-001 `
  -SupervisorTrustRootPath D:\release-roots\vulcan-supervisor.json `
  -ExpectedSupervisorTrustRootSha256 '<approved-vulcan-pin>'

pwsh -NoProfile -File scripts/publish-native-release-evidence.ps1 `
  -Gate Vulcan `
  -ReportPath D:\evidence\vulcan\report.json `
  -BindingPath D:\evidence\vulcan\binding.json `
  -CommitPath D:\evidence\vulcan\commit.json `
  -SourceCommit (git rev-parse HEAD) `
  -ReleaseBundleRoot build\release-bundle `
  -VulcanSupervisorTrustRootPath D:\release-roots\vulcan-supervisor.json `
  -ExpectedVulcanSupervisorTrustRootSha256 '<approved-vulcan-pin>'
```

The exchange/receipt TTL is an acceptance deadline: the producer and publisher
must validate the receipt while current, and the commit/index must be generated
inside the signed window. Later protected/tag readiness verifies the immutable
signature, capture-to-sign-to-expiry ordering, hash chain, replay uniqueness and
index freshness; it does not permanently invalidate retained evidence merely
because the short external exchange TTL has elapsed.

## Fail-closed common contract

- Inputs and out-of-band roots must be regular files reached without symlink,
  junction, mount/reparse traversal, or unstable replacement.
- JSON is bounded, strict UTF-8 without BOM, top-level object only, and rejects
  duplicate or case-ambiguous properties.
- Evidence directories use exact file sets. Hidden, extra, missing, linked, or
  non-regular entries fail closed.
- Trust roots are supplied by explicit out-of-band path plus protected approved
  lowercase SHA-256. Repository/private-key/self-approved roots fail closed.
- Reused challenge or attempt IDs are rejected across tracked indexes.
- Source provenance uses artifact capture commit **A** and evidence-only descendant
  release commit **R**. Runtime JAR bytes must remain exact across A/R; tracked
  evidence never tries to hash the commit that contains itself.
- Raw Vulcan event evidence contains a dedicated test UUID and behavioral check
  data. Handle it as security evidence; do not use a real player's identity.

After publication, add the native directory and index to Git, build the protected
R/A release bundle, and run `scripts/release-readiness.ps1` with every approved
out-of-band root/path/pin. A successful parser fixture proves the contract only;
it is always `fixture=true`, `release_eligible=false` and never claims a licensed
Vulcan event, a production punishment, kernel/DMA coverage, or Tencent ACE parity.
