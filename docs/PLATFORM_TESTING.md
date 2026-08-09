# Platform process testing

## Current gate

`scripts/platform-load-smoke.ps1` starts real server distributions and loads the
deployable MCAce shadow JARs. It is opt-in because the first run downloads and
prepares Minecraft server artifacts.

Pinned upstream inputs:

| Platform | Build | SHA-256 |
| --- | --- | --- |
| Velocity | 3.5.1 build 615 | `b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3` |
| Paper | 1.21.1 build 133 | `39bd8c00b9e18de91dcabd3cc3dcfa5328685a53b7187a2f63280c22e2d287b9` |

Artifacts are downloaded from PaperMC's official Fill service with a named user
agent and verified before execution. A mismatched cached file is quarantined
rather than executed or overwritten.

## Run

Requirements: Java 21, PowerShell, and network access on the first run.

```powershell
.\scripts\platform-load-smoke.ps1
```

The complete Phase 2 exit gate also starts a real Fabric client:

```powershell
.\scripts\platform-load-smoke.ps1 -WithFabricClient
```

An opt-in, display-capable evidence gate extends that run with one real signed
`GAME_RENDER_FRAME` request. Supply the actual local Loom development profile
name; the script does not guess it and never performs account login itself.

```powershell
.\scripts\platform-load-smoke.ps1 -WithFabricEvidence -FabricEvidencePlayerName Dev
```

After the signed request arrives, the operator must see and choose `Allow once`
in Minecraft. The script deliberately does not synthesize a click, capture a
window, capture a desktop, or access a cursor. It waits for the Fabric log to
confirm that the consent screen was shown, the server-signed `COMPLETE`
acknowledgement received by the client, and Velocity's content-free `evidence-audit.log` summary for
the requested `GAME_RENDER_FRAME`. It copies that audit file into the smoke run
directory; default evidence storage discards raw bytes.

Fabric Loom may need to fetch the official Minecraft assets on the first client
run. They can be prepared separately with:

```powershell
.\gradlew.bat :mcace-client-fabric:downloadAssets --no-daemon
```

Every invocation creates `build/platform-smoke/runs/<UTC timestamp>/` and leaves
earlier runs intact. It uses ephemeral loopback-only ports and performs:

1. Builds the Velocity and Paper deployable shadow JARs.
2. Starts Velocity with MCAce and waits for plugin initialization plus proxy
   readiness.
3. Copies only Velocity's public Ed25519 identity into the Paper plugin data
   directory.
4. Starts Paper, requires MCAce channel initialization and compares the logged
   pin fingerprint with the generated Velocity key.
5. With `-WithFabricClient`, starts Minecraft 1.21.1 with Fabric Loader 0.19.3,
   connects through Velocity, and requires the client, proxy, and Paper backend
   to agree on `VERIFIED` with risk 0.
6. Gracefully stops Paper, temporarily moves the pin aside, and restarts Paper.
7. Requires MCAce to fail plugin enablement with an explicit missing-pin error
   while Paper itself still reaches `Done`.
8. Restores the pin and gracefully stops both services; a timeout triggers
   process-tree termination.

The final `report.json`, positive/negative Paper logs, Velocity log, console
captures, artifact hashes, bind addresses, and assertions remain in the run
directory. A passing final line is:

```text
PLATFORM_LOAD_SMOKE_PASS|<absolute run path>
```

## Boundary

The base gate proves real artifact compatibility, plugin discovery/enable/disable,
root identity generation, explicit backend pinning, and missing-pin fail-closed
behavior. The `-WithFabricClient` gate additionally proves live custom-payload
registration, signed policy verification, four scoped manifests, a server-signed
authentication result, and the player-carried `mcace:admission` route into Paper.
Unit tests separately verify malformed frames, replay rejection, carrier UUID
binding, monotonic rollback protection, and local TTL expiry.

## Proxy-to-Paper signed admission player gate

The raw wire-peer gate starts a real Velocity or BungeeCord proxy process, a real
Paper process, and a bounded loopback Minecraft 1.21.1 protocol peer. The peer
completes configuration, receives the MCAce challenge, sends signed
`CLIENT_HELLO`/`AUTH_REQUEST` frames, and remains connected while the proxy sends
the player-carried signed `mcace:admission` snapshot to Paper. Paper must report
that it accepted the signed admission state; the test also requires no child
processes to remain.

The gate uses the normal proxy-to-backend forwarding configuration for each
adapter: Velocity `modern` forwarding with a per-run secret and Paper's matching
`proxies.velocity` configuration; BungeeCord `ip_forward: true` with Paper's
`settings.bungeecord: true`. The generated Velocity secret is never emitted in a
report and is removed during harness cleanup. This remains a loopback,
offline-mode transport test: it verifies forwarding compatibility and MCAce's
signed admission/pin boundary, not Mojang/Microsoft account authentication.

```powershell
.\scripts\proxy-admission-player-smoke.ps1
# Or run one adapter only:
.\scripts\proxy-admission-player-smoke.ps1 -Proxy Velocity
.\scripts\proxy-admission-player-smoke.ps1 -Proxy Bungee
```

Each result is kept in `build/runtime-player-probe/runs/<adapter>-<timestamp>/`
as `report.json` and `report.md`. The report records real TCP/login/configuration
progress, the signed MCAce result, Paper backend admission, and cleanup status;
it does not log raw signed frames or private keys.

This is a loopback-only, **offline-mode** integration gate. The peer uses a fixed
test player name and an ephemeral client signing key; it is not a Mojang/Microsoft
authenticated account and does not prove production online-mode forwarding. It
does prove the concrete proxy-to-Paper plugin-message path and Paper verification
against the per-run proxy public-key pin. Source-direction unit tests remain part
of the gate: client handshake input is player-only, backend/server injection
cannot reach the coordinator, and Paper rejects snapshots without a valid pinned
proxy signature.

The deterministic auto-connect and exit system properties are enabled only by
the Loom smoke run configuration. They do not alter normal packaged-client
connection behavior or weaken any signature, nonce, policy, or UUID check.

## Incremental disposition matrix gate

`scripts/disposition-proxy-matrix-smoke.ps1` is a separate, default-skipped
gate enabled by `mcace.runtime.disposition.enabled=true`. It runs real cases
strictly serially. Velocity and Bungee each use three named Paper backends and
a harmless test-only exact-SHA manifest to cover monitor-inert LIMIT plus
enforced LIMIT and QUARANTINE routing. The Bungee enforced cases are only
credited when the early route is first reported as `*_DEFERRED`, its one-shot
post-`ServerConnectedEvent` flush is reported as `DISPATCHED`, and Bungee's
separate `MCAce disposition route completion=SUCCESS` callback is observed.
`DISPATCHED` alone is deliberately not completion evidence.

The separately selected Velocity DENY reconnect case has a content-free
pre-reconnect lifecycle barrier. A bounded loopback status ping must first
observe an empty proxy registry; a test-only Velocity observer at
`DisconnectEvent` `PostOrder.LAST` must then emit a new fixed marker. The
observer never records player/event data, and LOGIN/CONFIGURATION disconnect
components are not decoded. Failure is reported only as the fixed
`clean_reconnect_stage`, `termination`, and `old_session_cleanup` enums; a
timeout never opens the second socket.

Each run deletes the forwarding secret, per-run private material, client cache,
signed policy/history, run-local observer JAR copy, and child stdout/stderr in `finally`. Only
a content-free `report.json` remains. Unimplemented actions remain
`NOT_EXECUTED`, `matrix_completed=false`, and `fabric_gui_coverage=false`; no
hostile Paper admission or Bungee Phase 2 claim is implied.
The evidence variant changes only the smoke shutdown point: it stays open after
authentication until the operator's one-shot consent results in a signed
`COMPLETE` acknowledgement. It never auto-consents.

## Federation proxy matrix gate

The client-carried federation path has a separate, explicit opt-in real-process
matrix. It starts an independent source proxy + Paper and target proxy + Paper,
using each of the four adapter combinations:

```powershell
.\scripts\federation-proxy-matrix-smoke.ps1 -Pair VelocityToVelocity
.\scripts\federation-proxy-matrix-smoke.ps1 -Pair VelocityToBungee
.\scripts\federation-proxy-matrix-smoke.ps1 -Pair BungeeToVelocity
.\scripts\federation-proxy-matrix-smoke.ps1 -Pair BungeeToBungee
# Run all four sequentially:
.\scripts\federation-proxy-matrix-smoke.ps1 -Pair All
```

The source raw peer first completes ordinary local `VERIFIED` authentication.
The harness then sends an explicit console `mcacefederation issue` command and,
only because this test itself was explicitly enabled, produces the same signed
consent response that a real Fabric user may approve. After receiving the signed
grant, the source client socket is closed. There is no source-to-target service
or live broker. The target peer reuses the still-live in-memory source session
key, completes a fresh local target authentication, signs the target-session PoP,
and submits the presentation. The gate requires an `OBSERVED` content-free target
audit, rejects a fresh-outer-envelope replay of the same assertion, keeps target
trust/risk/Paper admission at local `VERIFIED`/`0`, removes per-run forwarding
secrets, and leaves no owned process alive.

Reports are written under
`build/runtime-federation-matrix/runs/<source>-to-<target>-<timestamp>/`. They do
not contain grants, signed frames, nonces, session keys, challenges, private keys,
or raw federation presentations. The test is skipped during ordinary Gradle runs
unless `mcace.runtime.federation.enabled=true` is explicitly set.

This is a proxy/protocol matrix, not a Fabric GUI test. Its test-only raw peer
automatically exercises consent after the explicit opt-in command; it does not
claim that the real Fabric `Allow once` screen was rendered or clicked. That UI
remains a separate manual gate.

## Federation target-restart residual gate

Run the restart residual gate separately and only by explicit operator choice:

```powershell
.\scripts\federation-target-restart-residual-smoke.ps1
```

This Velocity-to-Velocity real-process probe proves the current, documented
residual rather than attempting to hide it: it stops the target proxy process
while retaining the same target identity/configuration and running Paper,
requires a newly authenticated target session to reject the old session-bound
PoP, then uses a test-only in-memory retained grant/key to sign a fresh PoP.
Because the target replay guard is intentionally in process memory, the fresh
unexpired assertion is expected to become advisory `OBSERVED` after restart.
The report therefore requires `residual_reacceptance=true`, content-free audit,
local `VERIFIED`/risk `0`/Paper admission invariants, and zero owned processes.
It is not durable cross-restart replay protection, not a Fabric GUI test, and
does not create any risk, admission, disposition, routing, punishment, evidence,
or source-target-network side effect.

## Folia player/runtime gate

Run the Folia-specific process gate separately:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\folia-process-smoke.ps1
```

The script asks PaperMC's official Fill API for Folia 1.21.1. Because no official
1.21.1 build is available, the recorded gate resolves and pins Folia 1.21.4-6
`ALPHA` with SHA-256
`dcf2333211c1468c8eddc482bc8549600818cc661a709124a79c752f8fa2ac3a` rather
than claiming exact 1.21.1 compatibility. It first proves missing-pin fail closed,
then starts a valid pinned server and a bounded test-only offline wire peer. The peer
completes login/configuration and sends one two-second, ephemeral-test-key-signed
admission snapshot. The gate requires region/entity admission consumption, global
expiry, PlayerQuit cleanup, no Folia thread-error marker, deletion of the private
test key, and zero residual processes.

Latest passing report:

```text
build/platform-smoke-folia/runs/20260808T202505461Z/report.json
```

This proves the backend scheduler and admission lifecycle against a real Folia
process and player entity. It does not prove online-mode authentication, a real
Fabric client on Folia, or production Velocity/Bungee forwarding into Folia.

## Evidence gate boundary

This gate is intentionally not suitable for headless CI. It requires a graphical
Minecraft/Fabric 1.21.1 development run, the standard Loom assets that may be
downloaded on first use, and an operator to inspect the consent UI. A passing
run proves the actual Fabric process, signed request, visible consent-screen
transition, one framebuffer capture, bounded chunk upload, client `COMPLETE`
acknowledgement, and proxy audit summary. It does not prove the semantic content
of the captured pixels, and it never requests `GAME_WINDOW` or `DESKTOP`.
