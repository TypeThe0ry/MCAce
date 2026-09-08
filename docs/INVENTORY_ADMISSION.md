# Opt-in inventory admission (development)

This is an administrator's entry rule, not a claim that MCAce has independently
confirmed cheating. The implementation currently targets Velocity only. It is
not a kernel/process scanner, an Xray classifier, or a permanent ban feature.

## Configuration

Create `inventory-admission.properties` in the MCAce Velocity plugin data directory:

```properties
enabled=false
denied-mod-ids=example_prohibited_mod
denied-selected-resource-packs=file/example-prohibited-pack.zip
```

These are examples, not a shipped cheat signature list. Replace them with the
exact loaded Mod IDs and selected resource-pack identifiers prohibited by your
server. Set `enabled=true` only when ready to reject matching connections, then
restart through the normal maintenance procedure. Do not use plugin hot reload.
Absent files or an absent enabled key leave the feature disabled. Disable it and
restart to roll back. No real server configuration is changed by this commit.

**This opt-in is independent of `enforcement.mode=MONITOR`.** That setting controls
the existing signed disposition path; it does not override this separately enabled
inventory admission rule. Existing trusted-source limits remain unchanged.

Matching is exact and case-sensitive. Lists are comma-separated, trimmed, unique,
at most 256 entries, each at most 256 characters with no control characters.
Empty lists are permitted. Trailing empty entries, duplicates, oversized values
and invalid booleans are configuration errors. The file is capped at 128 KiB.

Only loaded Mod IDs and selected resource-pack IDs are compared. An installed but
unloaded Mod or an unselected pack does not match. Missing telemetry is not a clean
verdict; use the separate client requirement for missing-client admission. Renamed
or hidden reports can evade identifier rules. These rules do not validate pack
content or detect unknown cheating programs; content-based detection remains a
separate capability.

## Execution and evidence

Initial and accepted dynamic manifests use the existing bounded audit handoff.
A matching finding carries only its reason and server receipt identity into the
Velocity scheduler. The physical-login lock is acquired before the coordinator
monitor. Session, sequence, receive time and age (three normal report intervals,
currently 900 seconds) are checked inside the same coordinator critical section
as the nonblocking disconnect API call. Report acceptance/removal cannot interleave
with that call. This does not wait for network completion.

There is one dispatch attempt per coordinator session. A failure or ambiguous
exception consumes that attempt to avoid repeated actions; it is logged as failed,
not successful. Successful/ambiguous attempts also stop pending route requests for
the physical login. Reconnection gets a new session and is evaluated again.
No risk score or SERVER_CONFIRMED authority is manufactured.

Logs contain `authority=ADMIN_CONFIGURED_INVENTORY`, a content-free finding and
result. `DISPATCHED` means `DISCONNECT_API_ACCEPTED`, with
`client-receipt-confirmed=false`. This is not a durable punishment receipt. Confirm
actual disconnection with live server/client evidence before claiming efficacy.

Queue saturation, audit evaluation failure or scheduler failure can prevent an
attempt. The current path is therefore not a guaranteed pre-backend admission
barrier. The client may enter before asynchronous rejection, and later pack
changes may wait up to the existing five-minute reporting cadence plus processing.
No low-latency or fail-closed entry guarantee is claimed.

## Remaining acceptance

An opt-in real-process case now exists:
`MinecraftProxyPlayerProbeTest.realVelocityInventoryAdmissionRejectsReportedModOnlyWhenEnabled`.
Set `mcace.runtime.inventory-admission.enabled=true` and supply the existing
`mcace.runtime` backend/proxy/JDK/prepared-tree paths, SHA-256 bindings, version and
protocol properties required by `RuntimeProcessAssets`. Gradle forwards the opt-in
to the test JVM. This creates two isolated Velocity/Paper environments: disabled
control must reach verified backend admission; enabled configuration prohibits
the raw peer's reported `fabricloader` ID and must produce both a disconnect API
log and protocol-disconnect/remote-EOF evidence. Do not copy that fixture rule into
a real server. This is a raw protocol peer, not Fabric GUI or real cheat detection.

Initial 2026-09-08 local result: **FAILED, not release evidence**. Paper 1.21.11 build 132,
Velocity 3.5.1-615 and JDK 21 assets passed content-binding preflight. The first run
had a cleanup-root mismatch that masked its startup error; the test now recognizes
its own dedicated work root and preserves original failures when cleanup fails.
The next attempt exposed the 30-second listener timeout while Windows private-path
ACL checks were still executing. Only this new case now allows 120 seconds for
listener readiness, retaining ACL checks and socket probing. The third attempt
started Velocity (54.21 seconds) and Paper (30.845 seconds), but the disabled
control timed out in the raw peer's frame read before passing its assertions.
The enabled case was not reached. That attempt's owned processes/work tree were
cleaned; the first failed cleanup left a diagnostic directory, not passing evidence.
Fixed-field handshake-stage diagnostics have since been added for the next rerun.

Later that day the full disabled/enabled Mod control passed once after the
Velocity handshake policy snapshot change; see the
[real-process evidence summary](evidence/inventory-admission-2026-09-08.md).
This is development evidence, not release acceptance. A second forced execution
also passed both controls; cached results are not counted as repeatability evidence.
When repeating this test with the same inputs, pass the test task's `--rerun`
option as well as the existing opt-in and exact asset properties. A successful
Gradle invocation showing `:mcace-runtime-integration:test UP-TO-DATE` did not
execute a new server/client control.

The companion `realVelocityInventoryAdmissionRejectsSelectedPackOnlyWhenEnabled`
case uses the signed selected-pack identifier `file/mcace-test-pack.zip` and only
the resource-pack deny selector. It requires the specific resource-pack finding
and remote disconnection, with the same disabled baseline. Its implementation
compiled and passed both controls once on Paper 1.21.11/Velocity/JDK 21; see the
same evidence summary for report/source hashes. It does not load a texture pack or
test Xray rendering/content recognition.

Both Mod and selected-pack controls also passed once on Paper 26.1.2 build 74,
Velocity and JDK 25 (two tests, four disabled/enabled cases, no skips). A separate
26.2 run is in progress. These results cover exact tested versions and reported
identifiers; they do not establish all 1.21.x/26.x versions or genuine GUI capture.

Protocol integration coverage now drives the normal ClientHandshakeEngine signed
authentication and bounded-update frames into ServerHandshakeCoordinator for two
cases: a fixture loaded Mod ID and a fixture selected resource-pack identifier.
Each starts clean, reports prohibited state, restores clean state and verifies the
old finding cannot dispatch, then reports prohibited state again and verifies one
current-receipt action callback. Disabled-policy evaluations remain NONE and the
test does not manufacture a risk-score or SERVER_CONFIRMED verdict. No executable
cheat or Xray texture is loaded: these are explicitly named fixture identifiers.
The action callback is a counter, not Velocity's Player.disconnect; this test is
protocol integration evidence, not GUI or actual disconnection evidence.

Verify a real enabled client with normal inventory, each prohibited input, removal
and reconnect, reporting delay, replaced report, and actual disconnect result.
Test all supported Minecraft versions and proxy parity before broad release
claims. Unit tests and successful compilation do not satisfy this live gate.
