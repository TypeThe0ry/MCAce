# Inventory admission real-process control test — 2026-09-08

Status: on 1.21.11, two passing Mod executions and one passing selected-pack
execution; on 26.1.2, both controls passed once. Development evidence, not
release-grade acceptance.

## Execution and provenance

- Checkout: `D:\Projects\MCAce`.
- Base commit: `170373f8886648bc302f1bc774539e9135b75d6d`.
- Uncommitted delta at execution: test-only failure/timing diagnostics in
  `MinecraftProxyPlayerProbeTest.java`; no product-code delta.
- Test source file SHA-256 (local bytes):
  `d6888b262fcf524964c1771eb93069b1816fa03049fb78ff0f771fe7265a8f48`.
- Test: `realVelocityInventoryAdmissionRejectsReportedModOnlyWhenEnabled`.
- Runtime: local Windows, JDK 21, Paper 1.21.11 build 132, Velocity 3.5.1-615,
  protocol 774, isolated loopback directories and ports.
- Gradle exit 0; one JUnit test, zero failures/errors/skips; test duration 225.892s.
- JUnit XML SHA-256:
  `32ed23067c30a89f109d2cf3d1ecdd8ce8ff211a7a7c069712df6477a5175fee`.

Product JAR SHA-256:

| Development artifact | SHA-256 |
| --- | --- |
| mcace-server-velocity-0.1.0-SNAPSHOT.jar | f1f9cf4488f02bfd41c5b01bf33314869dbba3999d9819832a9ae11955bd65b0 |
| mcace-server-paper-0.1.0-SNAPSHOT.jar | c3b56daf22d425beeb03e8a28c994aa40b88002741095849546953fe8d686fed |

These are development artifacts, not an exact-commit `v0.0.1` release bundle.

## Assertions actually exercised

The raw protocol peer submits its signed test manifest, including the harmless
`fabricloader` identifier. This identifier is deliberately configured as denied
for the enabled control; it is not a real cheat signature.

| Control | Required and observed by passing assertions |
| --- | --- |
| `enabled=false` | Client receives accepted authentication; verified backend admission occurs; no inventory disconnect dispatch marker occurs. |
| `enabled=true` | Client receives accepted authentication; inventory log contains `PROHIBITED_LOADED_MOD`, `DISPATCHED`, `ADMIN_CONFIGURED_INVENTORY`, and `DISCONNECT_API_ACCEPTED`; peer observes a non-NONE disconnect result (protocol disconnect or EOF). |

Both cases also pass owned-process cleanup assertions. Exact result markers:

```text
MCACE_INVENTORY_RUNTIME_CASE_PASS|enabled=false|real_proxy=true|raw_protocol_peer=true|fabric_gui=false
MCACE_INVENTORY_RUNTIME_CASE_PASS|enabled=true|real_proxy=true|raw_protocol_peer=true|fabric_gui=false
```

The assertions do not export which disconnect subtype occurred, so this summary
does not claim a particular kick message was displayed. Raw runtime trees and
private identity material were not uploaded. The local JUnit report is under
`mcace-runtime-integration/build/test-results/test/` and may be overwritten by
later runs; this document is a summary with a report hash, not a retained raw log.

## Boundaries and remaining verification

This proves one real proxy/backend run can accept a signed reported ModList and
apply an administrator-configured identifier rule with observable disconnection.
It does not prove authentic Fabric ModList collection, visible GUI consent, Xray
pack-content detection, external-process detection, resistance to client lies,
production precision/recall, the other Minecraft versions, or BungeeCord parity.
Earlier attempts failed; two passing runs are not a broad reliability study. No actual
cheat program was loaded and no screenshot is represented as having been taken.

## Forced repeat

The test was forced with the test task's `--rerun` option from clean commit
`c01a248` before editing the companion resource-pack test. Gradle reported one
task executed and 34 up-to-date; the test itself ran, exit 0. Both result markers
above appeared again. JUnit: one test, zero failures/errors/skips, 391.229 seconds.
Report SHA-256:
`75f9839573ba905a0ce7a0fe2d0a58d0221b4f0c13401779d2f9f6ae66e83415`.
The subsequent source edit occurred after test compilation and was not part of
this running test's bytecode. No additional build/test ran concurrently.

An earlier repeat invocation returned `test UP-TO-DATE`; it is expressly excluded
from the two executions counted here. This repeat covers the same 1.21.11 Mod
identifier case only, not the newly added selected-resource-pack control.

## Selected-resource-pack control

The companion `realVelocityInventoryAdmissionRejectsSelectedPackOnlyWhenEnabled`
completed on the same Paper 1.21.11/Velocity/JDK 21 runtime. Its test code is the
version committed as `8ea02b3` (the process started before that commit was made).
Local test-source SHA-256:
`07b17eb83bb867bf5b7356c983ba479c7e5761dcf9ce24b089cb65238e14cc47`.
JUnit: one executed test, zero failures/errors/skips, 238.015 seconds. Gradle exit
0. Report SHA-256:
`bb9f4d0e06dd5ebdab47d9029246a816b89fe5a4d0b92c8a507233734d7b51b1`.

Disabled configuration allowed accepted authentication and verified backend
admission. Enabled configuration contained only
`denied-selected-resource-packs=file/mcace-test-pack.zip` (no denied Mod IDs).
It produced the specific `PROHIBITED_SELECTED_RESOURCE_PACK` dispatch marker and
the peer's non-NONE disconnect observation. Both cleanup assertions passed.

```text
MCACE_INVENTORY_RUNTIME_CASE_PASS|enabled=false|real_proxy=true|raw_protocol_peer=true|fabric_gui=false|finding=PROHIBITED_SELECTED_RESOURCE_PACK
MCACE_INVENTORY_RUNTIME_CASE_PASS|enabled=true|real_proxy=true|raw_protocol_peer=true|fabric_gui=false|finding=PROHIBITED_SELECTED_RESOURCE_PACK
```

The selected-pack identifier is a signed test report, not a loaded texture ZIP.
This does not test Xray content, rendering, or genuine Fabric resource selection.

## Paper 26.1.2 / JDK 25

Both control methods completed with `--rerun`, protocol 775, Paper build 74,
Velocity 3.5.1-615 and the explicitly bound JDK 25 server executable. Gradle exit
0, one task executed and 34 up-to-date. JUnit: two tests, zero failures/errors/skips,
466.483 seconds. Selected-pack control: 227.488 seconds; Mod control: 238.975
seconds. All four disabled/enabled result markers were emitted and all assertion
paths, including owned-process cleanup, passed.

Paper input SHA-256:
`1d70b1dab9cf4a6de615209a536f3a45a2186240253c428213ce2188ab95e5f7`.
JUnit report SHA-256:
`b5fd62aefc00b70803be86893d1655d6199f48b8e3888accb2c464fb911f405a`.
The product/test implementation is the one committed in `8ea02b3`; subsequent
commits during this run changed documentation only. This was not a formal release
bundle build. The Mod/pack fixtures and all evidence limitations above apply.
26.2 testing has started separately; its outcome is not inferred from this run.
