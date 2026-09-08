# MCAce product and release reassessment

Status: proposed direction, grounded in current source; not a release approval.

## Objective and constraints

The core outcome is an opt-in Fabric client reporting its loaded mods and active
resource packs, with a server that evaluates fresh observations and executes an
explicit, auditable policy. Installing MCAce or verifying a signature is not proof
that a client is cheat-free. Client-controlled observations remain client claims.

Hard constraints are meaningful consent, bounded collection, session isolation,
honest evidence, and actions restricted to the administrator's configured scope.
Existing algorithms, package structure, signature ceremony, release workflow,
Vulcan integration, and federation architecture are design choices, not immutable
requirements. Removing a gate must be an explicit capability/scope decision, never
an edit that relabels missing evidence as passing evidence.

## Constraint review and decision rule

Review baseline: `a3e6815` (2026-09-08). Historical decisions are evidence to
reassess, not requirements to preserve automatically.

| Class | Current examples | Treatment |
| --- | --- | --- |
| Hard constraints | Truthful results, meaningful consent, bounded collection, connection isolation, administrator-scoped actions, actual external API requirements | Preserve the property; its implementation may still change. |
| Soft choices | Java/Fabric architecture, update cadence, package layout, notice adapters, release workflow, optional integration gates | Compare benefit with migration, technical risk, and validation cost. |
| Historical assumptions | Installation implies safety; signatures prove the client's observations; all integrations must block a core release | Reject the first two; explicitly review the release scope for the third. |
| Historical inertia | Adding receipts or adapter parity because they were previously next on a checklist | Require a demonstrated contribution to the product outcome before prioritizing. |

Incremental recommendation: retain the collectors, transport and session checks;
complete the observation-to-policy-to-action path with independently testable
execution results. A from-scratch alternative would separate a small inventory
admission product from optional behavioral and federation integrations. It offers
a simpler scope, but a complete code rewrite has no demonstrated performance or
reliability gain and incurs substantial migration and revalidation cost. Prefer
the smaller product boundary without assuming it requires replacing all code.

In particular, Bungee notice parity is useful consistency work, not proof of
detection or enforcement and not inherently the next release-critical feature.
Prioritize a real clean-client receipt, a controlled prohibited-artifact finding,
and an observable configured action over increasing the number of notice paths.
Missing telemetry must remain distinguishable from a cheating verdict.

Before changing any release gate, specify the capability included or excluded,
the user-visible documentation change, retained acceptance cases, and migration
impact. Removing an optional integration from core scope means NOT INCLUDED,
not PASSED. No existing gate is changed by this review.

## Initial source-backed gaps (before the implementations below)

- `ServerHandshakeCoordinator` originally used
  `lastArtifactObservationAcceptedAtEpochMs` for update rate limiting without an
  exposed freshness view. The query and optional notices described below now
  address visibility, but do not enforce a freshness lease. A live authenticated
  session is distinct from a fresh resource-pack view.
- The current production authority path ends in MONITOR; the README explicitly
  excludes LIMIT, QUARANTINE, DENY, kick, and ban from that path. Completing external
  receipts alone will not implement the user's requested server action loop.
- Client-reported transparent textures are heuristic evidence, not independently
  confirmed cheating. A server rule that rejects an explicitly prohibited pack
  must be described as a configuration/admission decision, not a cheat conviction.

## Alternatives and recommendation

Keep and extend the existing bounded collectors, signed transport, session checks,
and test coverage. Add a separate freshness/policy/execution state model. This has
less migration and validation risk than replacing Fabric, Java, or the wire protocol;
no measured benefit currently justifies a complete rewrite.

Recommended implementation order:

1. Expose separately authentication, observation availability/freshness, policy
   findings, and actual execution outcome. Use server receive time for freshness;
   reject duplicate/replayed updates as lease renewals. Clear state on reconnect.
2. Make update cadence and timeout explicit. Test no observation, fresh, stale,
   disconnect, rejected update, and unchanged-but-valid snapshot cases. Do not
   confuse stale telemetry with proof of cheating.
3. Add administrator-configured, session-bound, reversible admission actions with
   reason codes and execution receipts. Default to observation; do not permanently
   ban based solely on a transparency heuristic or missed heartbeat.
4. Verify real clean-client inventory and selected-pack changes, benign negative
   controls, controlled detection inputs, and actual server effects on all three
   supported versions. Separate fixture and real GUI evidence.
5. Revise the release contract in a reviewed change: core capability gates remain
   mandatory; Vulcan and federation gates should apply to releases claiming those
   integrations. Do not silently drop their promised functionality or claim their
   acceptance. Keep source provenance, hashes, CI, and truthful bilingual docs.

This note does not modify existing release scripts or mark any gate passed.

## First implementation: core receipt-freshness query

`ServerHandshakeCoordinator.artifactTelemetrySnapshot(playerId, maximumAge)` now
returns a read-only `ArtifactTelemetrySnapshot` for the current authenticated
session. Sequence zero uses the initial authentication receipt time; subsequent
sequences use the server's accepted-update time, not the client's timestamp.
The caller must provide a positive maximum age. Exact expiry is STALE; an
evaluation time before the receipt is CLOCK_ANOMALY. This wall-clock comparison
does not detect every possible clock adjustment and is not a monotonic timer.

Missing, replaced, or removed authenticated sessions return no snapshot. Retries
that receive an idempotent ACK and semantically rejected updates do not refresh
the receipt time. Authentication/admission is deliberately unchanged by this
query. The command integration below exposes this view; it is not connected to
enforcement. Client update cadence and operator-configured policy remain work.

Verification: targeted `ArtifactTelemetrySnapshotTest` and the complete
`HandshakeIntegrationTest` suite passed (35 tests, zero failures). Coverage includes
exact TTL boundary, pre-receipt clock anomaly, extreme Instant values, invalid
inputs, missing/pre-auth states, initial and dynamic receipts, lost-ACK retry,
rejected update, unchanged VERIFIED admission, replacement and removal.
The first test attempt incorrectly retried a client update after consuming its
ACK; the test was corrected to model a genuinely lost ACK before retrying.
No real-client runtime or complete repository test pass is claimed for this change.

## Administrator query integration

Velocity and BungeeCord now route `/mcaceobservation freshness <uuid> [seconds]`
through the same `ArtifactTelemetryQuery`. The command retains `mcace.admin.audit`
permission, checked before any lookup. UUIDs must have canonical form (case is
ignored); the diagnostic window defaults to three refresh intervals (currently
900 seconds) and is bounded to 1–3600. The initial 120-second default was incorrect
for the existing five-minute client cadence and has been corrected.
It is a query parameter, not a persisted policy or an automatic kick timeout.

Output includes the freshness classification, accepted update sequence, receipt
and evaluation timestamps, and diagnostic window. It excludes artifact identities,
file paths, player identifiers and session identifiers. UNAVAILABLE covers both
missing authenticated manifests and bridges without this optional capability.
The local Bungee coordinator bridge delegates to the shared core; the default
extension method reports no snapshot rather than inventing a fresh state.

Tests cover malformed/shortened UUIDs, argument bounds, no lookup on invalid input,
default/custom windows, exact expiry, content-free output, and permission-before-
lookup behavior in both proxy adapters. Real in-game command acceptance remains
pending; unit command dispatch is not a substitute for that runtime check.

## Client cadence audit and default-window correction

Both Fabric source trees already schedule a refresh after each accepted result,
even if pack/mod state is unchanged. The normal interval is five minutes. The
first detected change may send immediately; later changes coalesce behind that
interval. Work is single-flight; ACK timeout starts after transport send, and
failed scans/sends use bounded backoff. A genuine semantic rejection clears the
pending update and schedules a fresh scan; invalid/unverified replies do not
mutate the pending update. These are implementation observations, not latency
measurements on a running server.

The initial administrator-query default of 120 seconds was shorter than this
normal cadence. It now derives from three protocol refresh intervals (900 seconds)
instead of a disconnected literal. Regression tests cover the default remaining
FRESH at the normal interval and STALE at its exact expiry. Both Fabric scheduler
test sources also cover periodic unchanged-state refresh and cancellation.

This does not accelerate detection. In particular, a later pack change can still
wait up to the normal cooldown plus scan/transport time. A faster scoped change
notification, its server rate limit, and an explicit configured freshness policy
require coordinated client/server design before any automatic action is enabled.

## Optional Velocity stale-report notices

Velocity now reads `telemetry.notice.enabled=false` and
`telemetry.notice.max-age-seconds=900` from its `mcace.properties`. Existing files
without these keys remain disabled. Enabling requires an age greater than the
normal five-minute refresh interval and no more than 3600 seconds. Configuration
is loaded at plugin startup; the query command does not change it.

The existing heartbeat polling task also asks the coordinator for deduplicated
STALE/RECOVERED notice intents. Recovery requires a newer accepted observation
sequence: changing the clock alone cannot manufacture recovery. The adapter
rechecks the physical login and authenticated session under the existing lifecycle
lock before sending a content-free player message. It never changes risk/admission,
routes, kicks, or bans a player.

The log records DISPATCHED when the send API returns, FAILED on a send exception,
or SKIPPED_SESSION_CHANGED if the original connection is gone. DISPATCHED is not
client receipt confirmation. Each transition causes at most one attempt; a failed
notification is logged, not retried on every poll. These are operational logs,
not durable punishment receipts. No genuine runtime delivery is claimed yet.

This adapter integration currently covers Velocity only. Bungee's read-only
freshness command remains available but automatic stale-report notices have not
been connected there. The shared core poller and policy are covered by automated
tests; actual message delivery, production policy actions, and low-latency
selected-state notifications are still pending work.

Targeted validation passed: 40 core telemetry/handshake tests and 21 Velocity
configuration/observation-command tests, zero failures or skips. Velocity main
and test sources compiled. The tests do not drive a live player's network or
prove delivery of the optional notice; that remains a separate acceptance case.

## Execution-path audit and evidence clarification

The source already contains Velocity routing and disconnect adapters. The missing
core outcome should not be described as a complete absence of action code:
`DispositionEngine.provenanceAllows` excludes LIMIT and higher actions for
CLIENT_REPORTED observations, `AuthenticatedManifestDispositionEvent` requires
trusted authorization for them, and `VelocityDispositionExecutor` rechecks the
policy, current session, authorization context, admission baseline, and enabled
mode before invoking an adapter. Thus a client-only exact-hash match does not
automatically produce a kick under the current design. Completing an external
release receipt will not change that behavior.

A future administrator-configured prohibited-inventory admission rule must be
distinguished from an independently corroborated cheating verdict. Simply removing
the trusted-origin checks would conflate those meanings. This audit leaves those
checks intact while identifying that product decision and integration work.

Velocity synchronous disposition results now expose `executionEvidence()` and the
non-observe result log includes `execution-evidence` plus
`client-receipt-confirmed=false`. Legacy status identifiers are retained for
compatibility. NOTICE_SENT/WARN_SENT/CHALLENGE_AUDITED mean MESSAGE_API_ACCEPTED;
LIMITED_DISPATCHED/QUARANTINED_DISPATCHED mean ROUTE_REQUEST_ACCEPTED; DENIED means
DISCONNECT_API_ACCEPTED. A deferred intent is DEFERRED. All other statuses mean
NO_NEW_EFFECT_CONFIRMED, not proof that no earlier action ever happened.

These fields describe the synchronous call only. Route completion requires its
separate asynchronous result, disconnection requires live lifecycle evidence,
and client receipt requires actual client evidence. No screenshot challenge or
remote delivery is proven by sending a prompt. Bungee result logs have not been
changed by this patch.

Local offline targeted validation on JDK 21 passed: 4 event-contract tests,
8 trusted-authorization tests, 13 Velocity executor tests, and 12 deferred-route
tests (37 total, zero failures/errors/skips). The new test covers every executor
status's evidence classification. Velocity production and test sources compiled.
This is not a new real-server/client acceptance run or a release-bundle build.

## Queued observation identity

`AuthenticatedManifest` now carries a server acceptance timestamp (`receivedAt`)
and accepted `observationSequence`, zero for initial authentication. Its legacy
`authenticatedAt` field remains unchanged: for dynamic updates it is the client's
sampling timestamp, not the server receipt. The coordinator supplies both new
fields for accepted updates; the five-argument source constructor remains for
compatibility. Modules must be rebuilt together because the record shape changed.
No wire schema or client signature semantics changed.

Both Velocity client-manifest audit paths now hand only the event, sequence and
receipt time into the scheduler. Before advisory execution, a snapshot must match
the session, sequence and exact server receipt and be FRESH under a three-refresh-
interval window (currently 900 seconds). Otherwise the log records
STALE_OBSERVATION with NO_NEW_EFFECT_CONFIRMED. A newer accepted report therefore
invalidates an older queued report at this check. Provider/review events retain
their separate trusted authorization path.

This is a point-in-time advisory filter, not an atomic enforcement lease. An
update can arrive after the snapshot check. A future inventory-admission executor
must atomically bind its action to the current report and physical login rather
than reusing this check as sufficient high-impact authorization. Bungee advisory
scheduling has not gained this filter yet. No automatic prohibited-inventory
disconnect or live GUI acceptance is claimed by this change.

Validation: 34 handshake integration tests, 3 freshness snapshot tests, 1 manifest
metadata test, and 13 Velocity executor tests passed (51 total; zero failures,
errors or skips). The handshake test deliberately advances server time between
client preparation and acceptance to prove the two timestamps remain distinct.
Receipt matching covers session/sequence/time mismatch, exact expiry and a
pre-receipt clock anomaly. Velocity and Bungee main sources compile against the
new record. Scheduler/player end-to-end execution still requires live validation.

## Opt-in inventory rejection implementation

The next implementation now adds a separate administrator-configured inventory
path for Velocity. `InventoryAdmissionPolicy` compares exact loaded Mod IDs and
selected resource-pack identifiers; it does not promote observations to trusted
cheating authority. `inventory-admission.properties` is absent/disabled by default.
Its explicit enabled switch is independent of signed-disposition MONITOR mode.

Accepted initial/dynamic reports use the bounded audit handoff. When matched,
the adapter acquires its physical-login lock before calling the coordinator's
`executeInventoryAdmission`. The coordinator checks the receipt identity/freshness
and claims a one-shot attempt before the disconnect API call under its monitor.
Accepted updates and removal cannot interleave during this call. Route-state
locking occurs after leaving the coordinator monitor but before releasing the
physical-login lock. Exceptions are ACTION_FAILED and consume the attempt;
they are not silently retried. No risk-score or trusted authority changes occur.

This supersedes the earlier statement that no inventory disconnect path exists,
but does not complete its acceptance. Queue saturation, audit failure, delayed
reporting and lack of a pre-backend barrier remain limitations. Bungee parity,
real-client disconnect evidence, content-based Xray detection efficacy and final
release verification remain pending. See [inventory admission](INVENTORY_ADMISSION.md)
for configuration, rollback, evidence semantics and the complete limitations.

Local JDK 21 offline validation: 35 handshake tests, 2 inventory-policy tests,
2 Velocity inventory-config tests and 13 Velocity executor tests passed (52 total,
zero failures/errors/skips); Velocity main/test sources compiled. Tests cover
disabled defaults, selected-versus-installed matching, bounded exact selectors,
stale/replaced receipts, one-shot dispatch, failure deduplication and independent
claims after reconnect. This is not a live proxy/client disconnection test.

Follow-up concurrency validation: eight threads released from a shared barrier
submit the same receipt; exactly one returns DISPATCHED and seven return DUPLICATE,
with one callback invocation. Failure/reconnect coverage now exercises both a
false callback result and a thrown exception. The initial test compile failed on
a missing assertion import; it was corrected before verification. The rerun passed
36 handshake and 2 policy tests (38 executed, zero failures/errors/skips); the 15
unchanged Velocity tests were UP-TO-DATE, not newly executed. This exercises the
core synchronization boundary, not an actual network disconnect or GUI session.

Protocol-to-policy follow-up: the real client handshake engine generates signed
authentication and bounded dynamic reports for controlled Mod ID and selected
resource-pack identifier fixtures. The test starts clean, matches prohibited
state, replaces it with clean state (old action rejected), then reports prohibited
state again (one current-receipt action callback). Both cases preserve VERIFIED
SDK admission because the callback is a counter, not a real disconnect. The test
also verifies disabled rules do not match. Local offline JDK 21 validation passed
37 handshake and 2 policy tests (39 executed, zero failures/errors/skips).
This verifies the in-process protocol/policy/receipt chain without loading a cheat,
running a Minecraft GUI, or proving Velocity network effects.

## Real inventory runtime attempt (2026-09-08)

Added a separately opt-in Velocity/Paper process test with disabled/enabled
inventory rules and real remote disconnect evidence requirements. This is a raw
protocol peer, not a Fabric GUI. Latest actual execution failed in the disabled
control's frame read after both proxy and backend started; no enabled-rule
disconnect success is claimed. Earlier attempts exposed and corrected this new
test's cleanup-root handling and its cold Windows listener wait. ACL validation
remains intact. The latest executed run cleaned its owned processes and work tree.
See [runtime details](INVENTORY_ADMISSION.md) for the failure sequence and the
required property bindings. Two further diagnostic executions also failed before
ServerHello. The latest completed execution reached PLAY, finished configuration,
and received GameJoin, but recorded no ServerHello, authentication submission, or
AuthResult. This rules out a peer stuck in configuration for that run; handshake
startup/channel delivery remains unresolved. The enabled-rule case was not reached.
The bounded packet-ID trace contains protocol phase and IDs only, not packet
contents, player inventory, or credentials. The failed run is not release evidence.

Further live diagnostics on the same date showed successful current-player login
initialization and entry into challenge creation, followed by the same pre-hello
timeout without dispatch or creation-failure markers. This moves investigation
inside `ServerHandshakeCoordinator.begin()`, rather than assuming channel
registration or the login identity guard failed. That path synchronously reads
the policy and delegated key store; filesystem/ACL latency is a hypothesis, not
a confirmed root cause. A subsequent thread-attach attempt found the owned proxy
already terminated, so it supplied no blocking-stack evidence. All these runs
failed in the disabled control; none proves inventory rejection or GUI detection.

The next completed run captured MCAce-only stack frames before cleanup. At timeout
the handshake was inside `AuthorityFilePreflight.runWindowsAclHelper`, reached
through private-file validation, `DelegatedPolicyKeyStore.load`, policy `current`,
and coordinator `begin`. Heartbeat and expiry coordinator calls were also present
in the dump. Login initialization and challenge creation markers were true, while
dispatch and creation-failure markers were false. This confirms the ACL helper is
on the blocking handshake path at timeout, not that it is the only latency source.

The first optimization removes the empty relative-path component when a checked
directory equals its root. Both private and integrity directory traversals still
check the root once and every actual descendant; pre/post-read checks remain.
This removes redundant per-traversal Windows helper launches without caching ACL
results or relaxing access checks. The focused empty-root/nested-path regression
passed locally on JDK 21 (one test); this is not the complete filesystem security
suite. A real-process rerun has been started; runtime recovery is not yet proven.

### Post-optimization results

The real-process rerun completed with a timeout in the disabled control. The
captured stack still ran through the Windows ACL helper, delegated key loading,
policy retrieval, and coordinator `begin`. Login initialization and challenge
creation were observed, but neither challenge dispatch nor authentication was
observed. This run reached PLAY without observing GameJoin before timeout.
Removing duplicate root traversal did not restore the runtime handshake. The
run overlapped a filesystem regression suite, so it is not a controlled timing
benchmark and no performance percentage is claimed.

The complete `AuthorityFilePreflightTest` class finished on local Windows/JDK 21:
12 discovered, 8 executed, 0 failures, 0 errors, 4 skipped. The skips cover the
three POSIX-specific tests and the symbolic-link leaf/ancestor test; they remain
coverage gaps, not passes. These results validate the executed cases only.

The next design change must remove private-key filesystem I/O from the locked
handshake hot path. A prevalidated policy snapshot/refresh design must explicitly
retain expiration checks, signed policy and server-configuration binding, forced
rotation/revocation semantics, failure handling, and safe publication between
refresh and handshake threads. It must not treat installation as cheat-free or
use a stale/expired policy merely to pass runtime tests. This design change is
not implemented by the duplicate-traversal optimization.

### Bounded handshake policy snapshot implementation

Velocity now supplies the coordinator with a nonblocking policy snapshot reader,
not the disk-backed `current()` method. Initialization still loads/verifies the
policy and delegated key store. A single-flight scheduled refresh runs every
minute; successful disk-backed reads publish an immutable snapshot. Handshakes
reject absent snapshots, clock rollback relative to validation, snapshots aged
120 seconds or more, signature/time validation failures (zero clock skew), or
release-configuration mismatch. Rotation invalidates the old snapshot before
performing disk work. Failed refresh/rotation clears the snapshot. A concurrent
replacement during verification causes the reader to reject rather than return
the superseded snapshot.

This intentionally changes disk-change detection from per-handshake to periodic:
an already validated snapshot may remain usable until the next refresh detects
failure or its 120-second lease expires. It does not make an offline filesystem
change instant revocation, and does not retroactively revoke existing sessions.
The refresh path retains the existing key ownership, ACL, and signed-policy
checks. The manager monitor and private-key file I/O are not acquired by the
handshake reader. No stale snapshot is extended by reads or refresh failures.

The new focused snapshot test and the real-process inventory test have been
started; compilation succeeded, but successful runtime recovery is not yet
claimed. The change applies to Velocity, not BungeeCord's policy provider.

### Snapshot verification results

The focused snapshot test completed: one executed, zero failures/errors/skips.
It checks reading while another thread holds the manager monitor, the exact
120-second lease boundary, clock rollback, failed refresh invalidation, recovery,
and successful forced rotation publishing a different signer snapshot.

The real-process inventory test also completed but failed its authentication
acceptance assertion in the disabled control. Unlike the previous attempts, the
peer now observed ServerHello and sent authentication frames; configuration and
GameJoin were observed. The proxy recorded challenge creation and dispatch in the
same second with `sent=true`. No AuthResult was observed by the peer. Thus the
pre-hello blocking stage advanced, but end-to-end authentication, accepted ModList,
and enabled-rule disconnect remain unproven. The next investigation is the
authentication ingress/response and peer deadline, not the old pre-hello timeout.

### First passing inventory process control

A subsequent complete run passed both disabled and enabled controls on local
Paper 1.21.11/Velocity. The client observed accepted authentication in both cases;
disabled rules allowed verified backend admission, and enabled rules produced
the prohibited-loaded-mod dispatch marker plus remote disconnect evidence.
Only test diagnostics changed since the preceding failed run; therefore the
earlier authentication failure is not claimed fixed by those diagnostics and
repeatability remains to be established. See the
[evidence summary](evidence/inventory-admission-2026-09-08.md) for artifact/report
hashes, actual assertions, and raw-peer versus genuine Fabric/Xray limitations.

The Mod control subsequently passed a second forced execution, and the new
selected-resource-pack control passed its disabled/enabled execution on 1.21.11.
Both cover accepted authentication, the appropriate inventory rule, and remote
disconnect evidence, not genuine Fabric collection or Xray content analysis.
Paper 26.1.2 build 74 and 26.2 build 116 local JAR hashes match the asset manifest;
their prepared trees and JDK 25 are present. A 26.1.2/JDK 25 execution of both
control tests has started, but no 26.x passing result is claimed yet. Current
PR Windows checks were still running when inspected; this is not release approval.

The 26.1.2/JDK 25 run subsequently finished successfully: two tests, all four
disabled/enabled controls, zero failures/errors/skips. Its report hash and exact
Paper input are recorded in the evidence summary. A separate 26.2 build 116,
protocol 776, JDK 25 run is now active. Genuine Fabric collection and the remaining
release gates are not satisfied by these raw-peer process tests.

## Retained GUI run details (2026-09-08, UTC+08)

Source: `885e98dc4b0672147057955b5423b3bb3f7c0165`.
Wrapper: `scripts/platform-load-smoke.ps1`, Fabric 26.2, WithFabricEvidence,
RetainDiagnostics, ManualConsentTimeoutSeconds=300.
Run: `20260908T075131881Z-26_2-10910485f111f881fe8da195b3beca25`.

The isolated Velocity/Paper and real Fabric client started. Native Computer Use
showed the MCAce prompt without the previous firewall overlay. The client logged
the consent screen at 15:58:23. At 16:03:23 it logged that enablement was declined,
MCAce remained disabled, and no client frame was sent; a disconnect followed.
No user click was observed, so this is a timeout/disabled-path observation, not
evidence of a manual decline. The wrapper exited 1 with the 300-second consent
timeout error. It reported forcibly stopping its client after graceful timeout.

No ModList receipt, resource-pack detection, or execution success is claimed for
this run. Raw logs remain in `build/platform-smoke/runs/` and must not be uploaded
wholesale because the runtime tree contains local test identity material.

Invocation correction: `FabricEvidencePlayerName` asserts the observed profile;
it does not select the launch username. This attempt passed `McAceProbe`, while
Loom used `Player346`. The assertion was not reached because consent timed out.
Future runs should omit this optional assertion unless the actual profile is fixed
independently. This was a caller error, not a product detection failure.

## Inventory receipt summary (2026-09-08)

The three-version process-control results are now recorded in
[inventory evidence](evidence/inventory-admission-2026-09-08.md), including the
26.2 selected-pack baseline timeout and passing rerun. That intermittent timeout
is not considered fixed.

A gap in the existing GUI smoke was identified: authentication/evidence transfer
alone does not assert that the server received the client's Loaded Mod graph or
selected-pack counts. Velocity now exposes a read-only administrator command,
`/mcaceobservation inventory <uuid>`, protected by `mcace.admin.audit`.
It reports counts plus the current authenticated receipt's sequence/time/freshness.
No artifact identifiers/content are printed, and this is not a full ModList browser.
Counts are updated only alongside accepted authentication/dynamic telemetry;
receipt and counts are read atomically without changing admission or freshness.

Local verification on base `5df5c89` plus this change: Gradle exit 0, 40 tests,
zero failures/errors/skips. These are in-JVM integration/command tests, not
real Fabric GUI acceptance. Bungee and GUI smoke wiring remain pending.

| Test class | Tests | JUnit SHA-256 |
| --- | ---: | --- |
| InventoryTelemetryQueryTest | 2 | `6f494a8fedc7d079a4e5e2cce27714705ef14fefb495ee2d477020da79dd1ab5` |
| HandshakeIntegrationTest | 37 | `ee44ed3dc8a691d3950c105b85ed53ec5b9aa86404e3b03240c8f3094cc49f03` |
| MCAceObservationCommandTest | 1 | `3464cf8ce04d242e82c760141448ffd0d579cfcdbdaa9e430969c21d745eb94c` |

The local reports may be overwritten by later runs; these hashes identify this
run but do not constitute retained release-grade raw evidence.

### GUI inventory query wiring

On base `8a550f3`, the Fabric smoke now requests the authenticated inventory
summary after its real client has authenticated. The parser demands a fresh,
nonempty Loaded Mod count and bounded selected resource/shader counts, captures
only a newly appended response from the isolated proxy, and rejects ambiguity,
log replacement or process exit. UUID derivation uses the observed profile name
and the wrapper's existing offline-mode proxy configuration.

The content-free result is stored separately as `inventory-diagnostic.json`,
with `release_evidence=false`, `full_modlist_verified=false`, and
`xray_detection_verified=false`. This prevents the new diagnostic from silently
becoming a stronger formal release claim. The command cannot establish exact
Mod ID equality or texture-content detection from counts alone.

Validation: `test-smoke-inventory-receipt.ps1` and the existing
`test-platform-load-smoke-privacy.ps1` passed on local PowerShell Core and Windows
PowerShell 5.1. New tests cover UUID name case, malformed input, missing/stale
responses, invalid counts/timestamps, duplicate responses, old-log exclusion,
log rotation and stopped process. The new test is wired into both CI shell lanes.
No real GUI client was launched in this change; runtime acceptance is pending.

## Current-source GUI attempt: 0927339

Run `20260908T110358460Z-26_2-4b78a7209eb3004fa62b47614d7044b8`
used clean source `092733942fb87c540f09bef2f17ed49036f87cf7` and
`platform-load-smoke.ps1 -FabricTarget 26.2 -WithFabricEvidence
-RetainDiagnostics -ManualConsentTimeoutSeconds 300`.
Root JDK 21 and modern JDK 25 builds, smoke artifact checks, isolated Velocity
and Paper startup completed. Native Computer Use observed the separate real
Fabric enablement screen; the existing user Minecraft window was not operated.

The prompt rendered at 19:12:03 UTC+08. No accepted enablement marker was
observed. At 19:17:03 the server disconnected the client because MCAce client
authentication was required. The wrapper exited 1 for the unapproved
300-second enablement timeout, not for a failed inventory rule assertion.
No authenticated inventory diagnostic or render-frame transfer was produced.
The initial permission was not clicked by automation and is not assumed from
previous conversation consent.

Final report: `fabric_authenticated=false`, `enablement_consent_accepted=false`,
`cleanup_completed=true`, `cleanup_ports_free=true`,
`remaining_owned_process_count=0`. The client required forced termination after
its graceful shutdown timeout. Report SHA-256:
`046f397b5507619b2b7e62efb598628a138e30d13613463715890938f5700cb3`.
Raw diagnostics remain in the local run directory; private test identity files
were not uploaded. This is a disabled-path observation, not GUI acceptance.

An additional issue was observed at disconnect: Fabric reported a screen change
from `Netty NIO IO #0` rather than the render thread. Source inspection finds
the DISCONNECT callback calling `cancelAuthentication`, which invokes the consent
controllers' screen-restoring cancellation methods directly. Both Fabric source
variants contain this call pattern. A fix should invalidate connection authority
immediately while scheduling only UI work on the render thread, with stale-work
guards so cleanup cannot overwrite a new connection's UI. No fix or successful
retest is claimed yet. Do not automatically restart a consent-waiting GUI loop.

### Disconnect cancellation correction

On base `7969627`, both Fabric implementations now call the no-screen-restoration
cancellation path from DISCONNECT. Connection authorization, target claims,
authentication generation and pending work are cancelled immediately as before.
The three consent/capture controllers discard pending requests without inspecting
or changing Minecraft's screen. Pending references are volatile for cross-thread
visibility. Evidence cancellation still clears sensitive capture buffers and
cancels the request. Normal in-UI cancellation retains its existing restoration.

This supersedes the proposed deferred-UI cleanup: Minecraft owns the disconnect
screen, so MCAce should not restore a previous loading/consent screen at all.
No queued UI cleanup is created that could later overwrite a reconnect screen.
This is a focused correction, not a claim of a complete concurrency audit.

Local builds and selected tests passed on all exact targets: 1.21.11 (12 tests),
26.1.2 (13), and 26.2 (13), zero failures/errors/skips. Coverage includes new
background-thread enablement/explicit-file cancellation with no Minecraft UI
instance, no approval on cancellation, no repeated decline from a second cancel,
and existing enablement/attempt-generation contracts. The GUI privacy static
check also passed. The capture cancellation path was compiled and inspected;
the new behavioral tests specifically cover the two permission controllers.
No new real GUI run was started. Disappearance of the observed disconnect warning
and genuine authenticated inventory acceptance still require runtime verification.

## Full client regression and fixture reporting correction

On clean product source `4d4e2ec`, the complete client suites ran successfully:

| Module | Discovered | Skipped | Failures/errors |
| --- | ---: | ---: | ---: |
| client-common | 103 | 3 | 0 |
| Fabric 1.21.11 | 53 | 0 | 0 |
| Fabric 26.1.2 | 54 | 0 | 0 |
| Fabric 26.2 | 54 | 0 | 0 |

Thus 261 tests executed initially, with three coverage gaps rather than 264
passes. One skip was the unavailable symlink/reparse-directory test environment;
two were opt-in artifact classification tests without configured sample paths.
This was local JDK 21/JDK 25 execution, not live GUI/server acceptance.

Inspection of the fixture wrapper found a reporting defect: it hard-coded
`tests=3`, although `AntiCheatFixtureClassificationTest` has only two tests,
and trusted Gradle exit 0 without requiring a fresh, non-skipped JUnit result.
The wrapper now forces test execution with `--rerun` and validates fresh bounded
JUnit XML, the exact class/two case names, and zero failures/errors/skips.
DTD processing is prohibited. Report-only checks require the corrected count,
zero skipped tests and a JUnit hash. Historical reports claiming three tests
must not be used as accurate execution counts.

The two opt-in tests were then rerun successfully using the existing 26.2
metadata-only fixture (empty entrypoints) and resource-pack metadata ZIP; neither
was loaded as executable game code. Both actually executed with zero skips.
Report SHA-256:
`bbf0339276349174a6c146aea123c9a18a92c1817f244434048bdc6702823a85`.
JUnit SHA-256:
`e92052e8c00de4f5ff718d5d1a5a05decf6fa95c268e2a2aa0f8ae66a0595a82`.
The corrected report-only check passed. Positive/negative XML parser tests passed
on PowerShell Core and Windows PowerShell 5.1. This closes the two opt-in test
skips only for these controlled inputs; the symlink gap remains. Simulated
SERVER_CONFIRMED correlation is not a genuine provider event or production proof.
