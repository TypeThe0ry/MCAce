# Candidate 33e2dfe — build evidence, not release approval

Source and artifact source: `33e2dfec7b5d8cc864723d294cb23efa8c2158fe`.
The checkout was clean when the build began. This candidate includes the
authentication completion deadline fix and opt-in backend interaction guard.

## Execution

ClusterYourCodex reported a healthy controller but its registered Helio worker
was offline with stale telemetry at 2026-09-08T13:51:28Z. No remote job was
submitted. The controller used cached offline dependencies and one Gradle worker.

- Root JDK 21.0.12.1; modern Fabric JDK 25.0.4.1; Gradle 9.6.1.
- `releaseBundle`: exit 0, 3m 59s; 37 tasks, 11 executed.
- Nested modern Fabric build: exit 0, 2m 12s; 15 tasks executed.
- Bundle schema `MCACE_RELEASE_BUNDLE_V4`, version `0.0.1`, six deployable JARs
  and eight total entries; both source identities match the commit above.
- `scripts/version-compatibility-contract-smoke.ps1 -Execute` with both expected
  source arguments: `MCACE_VERSION_COMPATIBILITY_EXECUTE_PASS`, exit 0.

Local bundle: `build/release-bundle`.
Log: `build/release-candidate-33e2dfe-20260908.log`.
Previous bundle backup: `build/release-history/f055c2c-before-33e2dfe-20260908/release-bundle`;
all eight copied files were hash-verified before the new build.

## SHA-256

```text
1dd4afdfafe24cfb45a32661fbc74aeee131eb41f403acdef7e8c0ebc5db6d1c  mcace-client-fabric-1.21.11.jar
858fcd3b307316cd1c17526319f910638e92b67866059c9424919eed50a3d6e8  mcace-client-fabric-26.1.2.jar
a9e4eeb723769a9388d2810f54884fd479153165615af67e2e3450288bc1218b  mcace-client-fabric-26.2.jar
4189861d706faced83d6daffc17dd9cd7af2bd77c4733b8adea759949e58a448  mcace-server-velocity.jar
39ff560de46101713f438d0ec6cccd517c5bb206c1b589d2fc5922c415a2b38c  mcace-server-bungeecord.jar
55387fba8ba1e5629a9c30827ef13ed848b3ca42203ced7a0dc191617e55af41  mcace-server-paper.jar
```

## Acceptance remains incomplete

This build and packaging contract do not prove GUI consent, actual inventory
delivery, Xray or executable-cheat detection, interaction restriction under real
server event dispatch, or stable cold Folia authentication. The previous matrix
failure is retained; it is not converted into a pass by this build.
Current-candidate runtime checks and external release evidence remain required.
No tag or GitHub Release was created by this operation.
