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

## Source-backed gaps

- `ServerHandshakeCoordinator` stores `lastArtifactObservationAcceptedAtEpochMs`
  and uses it for update rate limiting. It does not expose a telemetry freshness
  lease. A live authenticated session is distinct from a fresh resource-pack view.
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
ignored); the diagnostic window defaults to 120 seconds and is bounded to 1–3600.
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

## Current runtime observation (2026-09-08, UTC+08)

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
