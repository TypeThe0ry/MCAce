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

The complete Paper module regression subsequently finished with exit 0 in
6m 31s: 86 discovered, 0 failures, 0 errors, 8 skipped. The skipped
platform/link/permission and licensed Vulcan checks are not validated by this
result. This rerun used the unchanged product source at documentation descendant
`d45b707e21e1cae5fdef718ff61031e21ec871a2`.
Log: `build/backend-interaction-guard-full-33e2dfe-20260908.log`;
SHA-256 `65f5a27a7d83505add268881117ce6662c254e6570681767fad0943841297294`.
The existing runtime admission observer only sends an empty action bar after a
snapshot callback; that marker does not validate this guard's event cancellation.

This build and packaging contract do not prove GUI consent, actual inventory
delivery, Xray or executable-cheat detection, interaction restriction under real
server event dispatch, or stable cold Folia authentication. The previous matrix
failure is retained; it is not converted into a pass by this build.
Current-candidate runtime checks and external release evidence remain required.
No tag or GitHub Release was created by this operation.

## Documentation descendant and strict runtime matrix

Release source `028c44c886fe959c9081604aff4d1a214d673b9c` was packaged through
`releaseBundle` with artifact source `33e2dfec7b5d8cc864723d294cb23efa8c2158fe`.
Build exit 0, 47 seconds. SHA256SUMS and all six product hashes remained unchanged;
the descendant compatibility contract also passed. The earlier invocation with
the old release-source manifest was rejected before server startup, as expected.

The subsequent strict Matrix V4 execution terminated with exit 1 on case 7:
`07-26.1.2-folia-velocity`. Cases 1–6 passed with zero remaining owned processes:
all four 1.21.11 Paper/Folia × Velocity/Bungee combinations, plus both 26.1.2
Paper proxy combinations. Cases 8–12 were not executed. This is not a full
matrix pass or an external supervisor receipt.

Failed run: `velocity-folia-2026-09-08T14-23-47-806472400Z`.
Report SHA-256: `2912b2f7ba275c593a708ca2b96757e023a58a068b13b07d785806e8b9deeda0`.
It connected, completed configuration, entered PLAY and received SERVER_HELLO,
but received no AUTH_RESULT. Authentication preparation took 10005 ms:
engine 65 ms, policy 9718 ms, frames 147 ms. Proxy logs record challenge dispatch
at 22:25:02 and LIMITED timeout at 22:25:07 local time. The failure was a socket
read timeout; all owned run processes were cleaned up. No deadline was relaxed.

The earlier 1.21.11 Folia/Velocity case passed in this run (401 ms preparation),
but that single success does not resolve the intermittent slow preparation.
These are real server processes with a raw protocol test peer, not real Fabric
GUI collection or cheating-software execution evidence.

Logs: `build/release-descendant-028c44c-20260908.log` and
`build/matrix-028c44c-retry-20260908.log`. The checkpoint retains six successful
cases; the failed raw report and invocation log are retained separately.
