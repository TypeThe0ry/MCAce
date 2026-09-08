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
required property bindings. New fixed-field stage diagnostics are compiled for
the next attempt, not represented as a completed successful rerun.

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
