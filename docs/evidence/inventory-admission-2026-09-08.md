# Inventory admission real-process control test — 2026-09-08

Status: passed once; development evidence, not release-grade acceptance.

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
Earlier attempts failed; repeated-run reliability remains unverified. No actual
cheat program was loaded and no screenshot is represented as having been taken.
