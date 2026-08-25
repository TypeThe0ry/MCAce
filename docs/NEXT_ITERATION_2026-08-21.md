# Next iteration status · 2026-08-21

This is the implementation and verification handoff for the next release
iteration. It is intentionally exact: an unlisted Minecraft patch is not
silently treated as compatible.

## Current status

| Workstream | Status | Evidence |
| --- | --- | --- |
| 1.21.11 client | Verified | protocol `774`, Java 21, final remapped JAR |
| 26.1.2 client | Verified | protocol `775`, Java 25, final named JAR |
| 26.2 client | Verified | protocol `776`, Java 25, final named JAR |
| Paper/Folia server matrix | 12/12 | 10 stable, Folia 26.2 beta |
| Dual-JDK strict build | 171/755 | 0 failures, 0 errors |
| Compatibility contract | 3/3 | exact metadata and fail-closed unknown versions |
| Anti-cheat fixtures | Passed | classification, integrity, replay, correlation |
| Real client load | Passed with boundary | Meteor initialized and Xray pack reloaded; no server connection |
| Real server detection/interception | Passed with boundary | Leaf 1.21.11 + GrimAC real-process runs emitted three `SERVER_CONFIRMED` `BEHAVIOR_HIGH_RISK` events and three loopback uploads; `MONITOR/NONE` remained intentional |
| Production SERVER_CONFIRMED authority | Pending | requires provider/profile/key/topology/action-ceiling freeze; Grim loopback is not production signed authority |
| Visible GUI consent | Pending | one connection-bound MCAce enablement decision; feature requests inherit it |
| Vulcan genuine event | Pending | licensed/current-source event delivery |
| Federation human handoff | Pending | source export → target import → live-through-TTL |
| Current HEAD Helio verification | Passed | Paper module 37 tests (0 failures, 0 errors, 1 skip) plus 14/14 static wrappers on `cc91c63…` |

## What changed in this iteration

- Added `scripts/version-compatibility-contract-smoke.ps1` and its PowerShell
  7/5.1 static contract test.
- Bound the compatibility report to the exact release bundle, commit-bound
  Fabric build IDs, nested-JAR shape, Java major, and protocol values.
- Made unsupported examples (`1.21.1`, `1.21.10`, `26.1`, `26.3`) explicit
  fail-closed cases.
- Rewrote the English and Chinese READMEs with current artifact hashes,
  verification commands, limitations, next gates, and diagrams.
- Added SVG verification dashboards that distinguish client-load proof from
  server-side detection proof.

## Verification commands

```powershell
# Exact release artifact and version contract
.\scripts\version-compatibility-contract-smoke.ps1 -Execute
.\scripts\version-compatibility-contract-smoke.ps1 -ReportOnly `
  -ReportPath .\build\compatibility-contract\report.json

# Real server process matrix
.\scripts\server-version-process-matrix.ps1 -Execute
.\scripts\server-version-process-matrix.ps1 -ReportOnly

# Defensive fixture classification (third-party code is not executed)
.\scripts\anticheat-fixture-smoke.ps1 -Execute `
  -MeteorJar <absolute path> -MeteorSha256 <sha256> `
  -XrayResourcePack <absolute path> -XraySha256 <sha256> `
  -TargetVersion 1.21.11
```

## Next acceptance gates

1. Run the single visible `Enable MCAce` decision once and verify that decline/close
   leaves all MCAce traffic disabled; run the three target compatibility checks without
   opening per-feature prompts.
2. Freeze the production `SERVER_CONFIRMED` provider/profile/key/topology and
   action ceiling; keep the real Grim loopback record separate from that claim.
3. Supply the licensed Vulcan 2.9.0 JAR, rerun current-source structural
   preflight, isolated Paper enablement, and one genuine external event.
4. Run the real Fabric federation handoff with both visible consent decisions.
5. Run protected exact-commit CI and publish a tag only after the bundle and
   source commit match.

## Anti-cheat interpretation

The real-client smoke is intentionally not an effectiveness benchmark. It proves
that a third-party client mod and Xray resource pack can be discovered and loaded
by the 1.21.11 client. It does not prove that the server saw a cheat action,
detected it, or enforced a response. The defensive policy therefore keeps
`CLIENT_REPORTED` at observation-only and requires server confirmation or durable
administrator authorization for high-impact actions.
