# Runtime protocol testing

## Purpose and boundary

The `mcace-runtime-integration` module verifies the Level 1 protocol across real
JVM process and loopback TCP boundaries. It is a deterministic defensive test
harness, not a production server. Real Velocity/Paper process loading and the
Fabric player-flow are covered by the separate platform smoke gate.

The JUnit parent starts one server JVM on an ephemeral loopback port, then starts
four known-good and nine deliberately malformed client JVMs concurrently. The
server accepts exactly thirteen connections, gives each connection an isolated
handshake coordinator, and exits after all results are emitted.

## Run

Requirements: JDK 21. No Docker, Minecraft installation, or external network is
required.

```powershell
.\gradlew.bat :mcace-runtime-integration:test --rerun-tasks --no-daemon
```

The XML evidence is written to:

```text
mcace-runtime-integration/build/test-results/test/
  TEST-com.ellan.mcace.runtime.RuntimeNetworkIntegrationTest.xml
```

## Real proxy/backend admission probe

`MinecraftProxyPlayerProbeTest` is a separate opt-in process integration test.
It uses cached, pinned Velocity/BungeeCord and Paper artifacts prepared by the
platform smoke, then starts each proxy and Paper on fresh loopback ports. Its
small raw Minecraft 1.21.1 peer is intentionally not a client product: it only
implements enough login/configuration and custom-payload transport to prove the
signed handshake and proxy-to-Paper admission snapshot route.

```powershell
.\scripts\proxy-admission-player-smoke.ps1 -Proxy Both
```

The test is offline-mode only, uses a fixed test player identity and an ephemeral
client signing key, and has no Mojang/Microsoft account login. Velocity uses a
test-only modern-forwarding secret with Paper's matching proxy configuration;
BungeeCord uses IP forwarding with Paper's Bungee compatibility setting. A pass requires
the proxy authentication result and Paper's `Accepted signed MCAce admission
state` marker. It does not claim online-mode identity forwarding, a graphical
Fabric session, or Folia forwarding through either proxy.

## Opt-in real disposition matrix (incremental gate)

Run this gate only when real proxy processes are intended. It is skipped by a
normal Gradle test invocation unless `mcace.runtime.disposition.enabled=true`
is set; the wrapper sets that property and runs Velocity before Bungee, never in
parallel:

```powershell
.\scripts\disposition-proxy-matrix-smoke.ps1 -Proxy Both
```

Each Velocity and BungeeCord case uses one real proxy and three independently
named Paper backends (`lobby`, `limited`, and `quarantine`). The administrator
console publisher signs and activates a harmless test-only exact-SHA policy; the
raw peer authenticates during CONFIGURATION. The wrapper runs the real
`MONITOR_LIMIT`, `ENFORCE_LIMIT`, and `ENFORCE_QUARANTINE` cases serially for
the selected platform. Bungee's two enforced cases additionally require its
initial `*_DEFERRED` result, the one-shot post-`ServerConnectedEvent`
`DISPATCHED` marker, and the independent terminal `route completion=SUCCESS`
callback; dispatch alone is not credited as a successful route.

`ENFORCE_DENY_RECONNECT` is an independent, explicitly selected gate and is not
yet part of the wrapper's passing set. Its second same-identity connection is
fail-closed behind two content-free old-session barriers: a bounded loopback
status ping must report an empty Velocity player registry, then a test-only
`DisconnectEvent` subscriber at `PostOrder.LAST` must emit a new fixed marker.
No disconnect component is parsed. A timeout or unavailable observer prevents
the second socket from being opened. The sanitized report exposes only
`clean_reconnect_stage`, `termination`, and `old_session_cleanup` fixed enums,
plus booleans; it does not claim a persistent ban state.

Every case deletes its forwarding secret, generated identities, client cache,
signed policy/history, run-local observer plugin copy, and redirected process output. Its run
root retains only a sanitized `report.json`; no hash, rule identifier, policy
bytes, key, session, UUID, raw frame, path, log content, or disconnect reason is
retained. `fabric_gui_coverage=false` and `matrix_completed=false` remain
mandatory until all requested cases are independently proven.

## Opt-in real Paper/Folia hostile-admission gate

`paper-folia-hostile-admission-smoke.ps1` is a separate local defensive gate for
the backend admission boundary. It is not a scanner, exploit tool, or Minecraft
client product. The caller supplies one already obtained server JAR; the wrapper
does not download an artifact or contact a public server. It starts that JAR only
on an ephemeral `127.0.0.1` port, generates one per-run Ed25519 pin, and uses the
test-only raw peer to send bounded custom-payload fixtures. All Gradle subprocesses
use the already installed Gradle 9.6.1 distribution and local dependency cache
with `--offline`; a missing distribution, exact Paper API cache, server JAR, or
test plugin artifact fails closed. Every Gradle subprocess also has an explicit
timeout which terminates its process tree.

The wrapper requires the modern .NET process APIs exposed by `pwsh` 7, including
`ProcessStartInfo.ArgumentList` and process-tree `Kill(boolean)`. Windows
PowerShell 5.1 is rejected during preflight as the fixed
`POWERSHELL_PROCESS_API_UNSUPPORTED` result, before Gradle or a Minecraft server
can start. This is a runner-host compatibility failure, not a Paper rejection.
The sanitized report also carries a fixed `failure_stage` enum plus content-free
booleans for process API support, Gradle start/zero exit, refreshed build
outputs, work/key/server preparation, log creation, and each readiness marker.
Unknown platform exceptions are mapped to a fixed `<STAGE>_INTERNAL_ERROR` enum;
exception messages are never retained.

Before the offline build, the wrapper records the existing Paper and test-only
observer JAR timestamps. A passing build requires the Gradle process to start,
exit zero, emit the two requested task markers and `BUILD SUCCESSFUL`, and
refresh both output JARs. A stale JAR that merely exists from an earlier run
cannot satisfy the gate.

```powershell
# Use an already verified local Paper or Folia server JAR. Run one platform at a time.
.\scripts\paper-folia-hostile-admission-smoke.ps1 -Platform Paper `
  -ServerJar .\build\platform-smoke\cache\paper-1.21.1-133.jar

.\scripts\paper-folia-hostile-admission-smoke.ps1 -Platform Folia `
  -MinecraftVersion 1.21.4 `
  -ServerJar .\build\platform-smoke-folia\cache\folia-1.21.4-<build>.jar
```

`folia-process-smoke.ps1` remains a separate artifact-acquisition and broad
platform smoke with its own explicit network boundary. The hostile-admission
gate never invokes it and never downloads a Paper/Folia artifact. After startup,
the hostile gate parses the current work log's `[bootstrap] Loading Paper|Folia
... for Minecraft ...` banner and requires both the selected platform and
`-MinecraftVersion` to match exactly. A mismatch is retained only as a fixed
enum, never as banner text.

The gate first proves that one snapshot signed by the pinned proxy key is
accepted. It then proves that an unpinned signer, a wrong carrier UUID, a replay
after one permitted baseline send, an expired snapshot, an over-budget plugin
frame, and a valid frame sent on the wrong channel do not add another accepted
backend admission. Because `PaperAdmissionReceiver` invokes its local session
observer only after acceptance, the absence of an additional accepted admission
also proves no admission/session action was installed for those hostile fixtures.
A second test-only Paper/Folia plugin independently observes the installed SDK
snapshot, schedules one harmless empty action-bar send on the live player's
entity scheduler, and emits only the fixed
`MCACE_RUNTIME_OBSERVER_LOCAL_ADMISSION_ACTION_EXECUTED` marker. The pinned
baseline and the first permitted replay frame must each add exactly one accepted
marker and one local-action marker; every hostile-only frame and the replay's
second frame must add neither.

Before every case the wrapper captures fresh accepted/quit-cleanup/local-action
marker counts and requires them to remain unchanged for a bounded pre-case
window. After the peer exits, only that case's exact deltas are accepted, and the
expected counts must remain unchanged for a further two-second stability window.
A delayed marker from the previous same-UUID connection therefore fails the next
case instead of being consumed as its evidence.

The retained `report.json` deliberately contains only a fixed schema/platform
enum and booleans for the seven assertions, temporary-material cleanup,
process cleanup, and final outcome. It has no player UUID, key, fingerprint,
hash, session value, raw frame, server log, or workspace path. All generated
keys, raw-peer reports, copied JARs, logs, and server work are removed in
`finally`; the wrapper fails if a process whose command line belongs to the run
remains alive.

## Scenario matrix

| Scenario | Expected result | Risk | Protocol violation |
| --- | --- | ---: | --- |
| Four independent known-good clients | `VERIFIED / VERIFIED` | 0 | No |
| Replayed `CLIENT_HELLO` | `LIMITED / UNKNOWN` | 100 | Yes |
| Forged client signature | `LIMITED / UNKNOWN` | 80 | Yes |
| Oversized frame declaration | `LIMITED / UNKNOWN` | 80 | Yes |
| Truncated frame body | `LIMITED / UNKNOWN` | 80 | Yes |
| Malformed Protobuf | `LIMITED / UNKNOWN` | 80 | Yes |
| `AUTH_REQUEST` before `CLIENT_HELLO` | `LIMITED / UNKNOWN` | 80 | Yes |
| Asserted UUID differs from connection UUID | `LIMITED / UNKNOWN` | 50 | Yes |
| Server root is not pinned | `LIMITED / UNKNOWN` | 20 | No response/timeout |
| Client build is incompatible with policy | `LIMITED / UNKNOWN` | 20 | No response/timeout |

Malformed input is controlled and loopback-only. It verifies fail-closed
admission without creating a ban or other irreversible action.

## Evidence semantics

The server emits a trace for each complete frame with scenario label,
direction, sequence, byte length, and SHA-256. Transport rejection classes and
final admission snapshots are also emitted. Raw frames and private keys are not
logged. Ed25519 keys, nonces, session IDs, the ephemeral port, and resulting
frame hashes intentionally vary between runs; the scenario set and asserted
outcomes are deterministic.

The JUnit parent forcibly terminates a child that exceeds its bound, and its
`finally` cleanup terminates the server if an assertion or child fails. A clean
run must report one test, zero failures, zero errors, and zero skipped tests, with
no remaining `RuntimeNetworkMain` process.
