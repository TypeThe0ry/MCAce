# Detection, disposition, and evidence contract

## Status

This document defines the MCAce detection safety contract. The current
implementation provides signed policy structures, a strict protocol-to-core
compiler, one platform-neutral proxy evaluator, neutral Fabric artifact
metadata, proxy-safe authenticated manifest fragmentation, and live
Velocity/Bungee policy adapters. Both proxies derive the initial authenticated
manifest and every accepted dynamic artifact snapshot through the shared signed-
policy evaluator, then hand the resulting content-free, session-bound
`AuthenticatedManifestDispositionEvent` to the platform proxy executor. This
path never rewrites authentication or admission. Under an active signed policy,
and after current-session, `VERIFIED`-admission, and policy revalidation,
`NOTICE`, `WARN`, and the content-free `CHALLENGE` message may execute.
Client-origin `LIMIT`, `QUARANTINE`, and `DENY` remain non-executable without
durable `SERVER_CONFIRMED` or `ADMIN_REVIEWED` authority. Fabric can now collect one
  Minecraft render frame only after the connection-level visible `Enable MCAce`
  decision; the render request itself does not open a second prompt.
Operating-system window and desktop capture remain unsupported, zero-content, and
disabled. The repository has an explicit opt-in encrypted content-store control,
but no raw-image reviewer retrieval UI; default operation discards raw bytes.

After an accepted authentication result, Fabric may send an optional complete
`ArtifactObservationUpdate`. The ordinary first refresh is due after five
minutes, while the first detected loaded-Mod, resource-pack, or shader-pack
change before any dynamic update has been accepted may pull that first attempt
forward immediately. Once one dynamic update is accepted, later state changes
coalesce behind the next full five-minute interval. The five-minute rule limits
new semantic acceptances; it does not prohibit retry transport. Scan or
transport failures use bounded exponential backoff from one to thirty seconds.
Once every fragment has reached the transport API, a thirty-second semantic-
result timeout starts. A lost result retains and retransmits the exact pending
update with fresh transfer IDs, envelope nonces, and signatures.

The update rescans only the same signed-policy integrity scopes; it never accepts
server-supplied paths, does not scan private files, and is not required for a
session to remain verified. Each update is separately signed and session-bound,
has a 256 KiB / 16-chunk / 512-entry ceiling, and binds its strict update
sequence, authentication-time manifest root, prior/current aggregate roots,
policy digest/sequence, selected resource and shader packs, loaded Mod graph,
authenticated capability list, and an `observed_at` value no older than one
minute.

For every complete parseable update, the server returns a signed
`ArtifactObservationResult` bound to the authenticated session, update sequence,
aggregate root, and SHA-256 of the complete canonical
`ArtifactObservationUpdate` bytes. The client advances its dynamic sequence,
aggregate-root chain, and next five-minute cadence only after verifying an exact
`ACCEPTED` result. An invalid, forged, stale, replayed, or mis-bound result cannot
mutate client state and leaves the exact payload pending for timeout recovery. A
valid negative result consumes that pending payload and schedules a fresh
snapshot. A signed `RATE_LIMITED` result supplies a retry time that the client
bounds between its local backoff and one normal interval.

The server idempotently accepts a lost-result retry only when sequence, aggregate
root, and the full-update SHA-256 all match the update it already accepted.
Reusing the same sequence and root while changing selected packs, loaded Mods,
capabilities, or another non-root field is rejected rather than inheriting the
earlier acceptance. Rejection, replay, expiry, scope escape, queue saturation,
or rate limiting never changes an already `VERIFIED` admission.

This optional channel is telemetry, not a heartbeat, an ongoing freshness lease,
or continuous attestation. The server validates `observed_at` freshness when an
update is ingested, but no later timer revokes admission or expires the remembered
dynamic manifest merely because updates stop. A client that remains connected
but silent on this channel can therefore leave the server's last dynamic view
stale until a later accepted update, session replacement, or disconnect cleanup.

Each proxy also keeps a bounded, durable dynamic-observation audit journal for
operations. Its entries contain only player UUID, observation/evaluation times,
observation and consistency-issue counts, aggregate action counts, and policy
refresh state. They contain no paths, filenames, artifact identifiers, hashes,
rule IDs, raw manifests, screenshots, or other private content. Administrators
with `mcace.admin.audit` may use `/mcaceobservation status` or
`/mcaceobservation player <uuid> [1-100]`; both commands are strictly read-only
and have no risk, admission, or disposition effect.

This no-effect guarantee applies to the journal and its read-only commands; an
accepted dynamic manifest may still produce the separately described, bounded
session-bound disposition event.

Paper/Folia world and game mode are available to a separate shadow comparison path. The backend
report is bound to the latest proxy-signed admission transport sequence, while Velocity/Bungee
derive backend identity from the event-supplied backend connection that carries the target player.
The adapters do not depend on an eventually consistent current-server pointer; the runtime still
requires the exact authenticated session, backend, UUID, admission sequence, monotonic report
sequence, and freshness binding. The shadow runtime evaluates the latest authenticated manifest with
`proxy/backend/world/gameMode` populated but emits only aggregate counts; it cannot create
`AuthenticatedManifestDispositionEvent` or call either proxy disposition executor. This context
does not upgrade a client-reported artifact into `SERVER_CONFIRMED` provenance.

The opt-in real-process Fabric evidence smoke uses the ordinary signed proxy
request and the same connection-level enablement screen. It waits for one human
`Enable MCAce` action, then verifies bounded Begin/Chunk/Commit upload and the
server-signed `COMPLETE` ACK, and Velocity's content-free audit line. It has no
automatic consent, desktop or window capture, mouse automation, or
account-authentication bypass. Decline/close keeps MCAce disabled and sends no
handshake, evidence, or federation frame.

The controlled anti-cheat fixture smoke exercises the same provenance boundary
without executing third-party code: a bounded mod/resource-pack fixture is
collected as `CLIENT_REPORTED`, and an independent same-session server signal is
fed through `ServerBehaviorCorrelator`. Both observations must upgrade to
`SERVER_CONFIRMED`/`CONFIRMED`; the fixture report records
`OBSERVE_ONLY_UNTIL_SIGNED_POLICY`, so no kick, deny, or ban is implied. This
proves client/server correlation logic only, not a real public-server detection
rate or kernel-level ACE capability.

## Trust and provenance

Every observation must retain one provenance value:

- `SERVER_CONFIRMED`: derived from proxy/backend authority, such as a replayed
  nonce, invalid proxy signature, impossible server state, or an authenticated
  behavior event.
- `CLIENT_REPORTED`: supplied by the Fabric Mod, including file manifests,
  resource-pack state, configuration digests, and screenshots.
- `INFERRED`: produced by correlation or a heuristic rule.
- `ADMIN_REVIEWED`: the result of an identified operator review.
- `UNAVAILABLE`: the requested observation was declined, unsupported, expired,
  or failed for an operational reason.

`CLIENT_REPORTED`, `INFERRED`, and `UNAVAILABLE` observations are rejected by the
evaluator as sole candidates for `LIMIT`, `QUARANTINE`, or current-connection
`DENY`; their rule explanation is `advisory-origin-cannot-enforce`. The product
has no automatic or permanent `BAN` disposition. High-impact selection requires
`SERVER_CONFIRMED` or `ADMIN_REVIEWED` provenance in addition to all ordinary
policy, scope, confidence, admission, and execution-mode gates.

### Trusted high-impact authorization

A trusted provenance label alone is insufficient for execution. Every high-impact
event must also carry a session-bound authorization ID and the V3 session,
review-input, and execution-context commitments produced by the trusted authorization
runtime. For administrator review, an operator with
`mcace.admin.disposition.review` submits:

```text
/mcacedisposition review <player> <ticket> <mod|resource-pack|shader-pack|config> <identifier> <version> <sha256>
```

The command accepts bounded single-token metadata and an exact SHA-256, but it does
not accept an action. It resolves the player's current authenticated `VERIFIED`
session, evaluates the observation against the active signed policy, appends the
strict 16-column TSV record beginning with `v3` to
`trusted-disposition-authorizations.log`. The record includes the authorization ID,
operator/ticket, selected action/rule, policy identity, and three commitments. The
runtime forces that record to disk and only then queues the event. Missing policy,
no winning rule, stale/non-verified session,
journal initialization/write/quota failure, or unavailable execution queue results
in no action.

Immediately before execution, the proxy revalidates the exact current session and
`VERIFIED` admission inside the same physical lifecycle. In one policy-atomic
boundary it also requires the exact execution-context commitment, active policy
identity/status/expiry, current winning rule, and `rule.action == event.action`.

The retained 2026-08-21 three-target Velocity/Bungee V3 matrix passed 18/18 administrator-reviewed
exact-hash cases (6/6 on 1.21.11, 26.1.2, and 26.2). LIMIT and QUARANTINE completed
on their distinct routes, while DENY closed only the current connection and allowed
a clean independent-session lobby reconnect. Every strict 16-column V3 authorization
journal entry was persisted before execution, and Execute plus ReportOnly passed. The
sanitized commit-bound triplets are in
`docs/evidence/disposition-current-2026-08-21.json` and declare
`authorization_contract=UUID_CONTEXT_COMMITMENT_V3`.
This is historical real-process `ADMIN_REVIEWED` coverage for its bound source; no
real-process producer currently
upgrades an artifact observation to `SERVER_CONFIRMED`, and the shadow backend context
path must not do so. The August 13 aggregate remains retained history.

## Detection categories

Rules classify artifacts and observations rather than product names. Supported
categories are expected to include:

- cheat or modified client Mod artifacts;
- automation, macros, pathfinding, and bot helpers;
- X-ray, entity-highlight, and information-leaking resource/shader packs;
- unapproved utility, accessibility, compatibility, and administrator-approved
  artifacts;
- client-build, loader, manifest, signature, replay, and protocol anomalies;
- server-confirmed behavior correlations from Paper/Folia and anti-cheat plugins.

An exact artifact hash is stronger than a filename or display name but still
identifies only that artifact. An unknown artifact is not a confirmed cheat.

## Dispositions

The policy engine may return only these operational actions:

| Action | Meaning |
| --- | --- |
| `ALLOW` | Explicit, narrow exception for a selected artifact/version/scope. |
| `OBSERVE` | Audit without player-visible impact. |
| `NOTICE` | Non-blocking compatibility or rules notice. |
| `WARN` | Explain a risk and request remediation. |
| `CHALLENGE` | Request re-authentication or optional additional evidence. |
| `LIMIT` | Remove access to a specific high-value feature or route. |
| `QUARANTINE` | Place the session in a review-safe server or mode. |
| `DENY` | Reject the current connection/transfer; this is not a ban. |

Foundation-security rules for invalid signatures, replay, or protocol forgery
cannot be overridden by an artifact allowlist. High-impact actions require a
signed, versioned policy, an explanation, audit, rollback, and an appeal route.

## Screenshot scopes

Screenshot scopes are intentionally non-substitutable:

| Scope | Definition | Initial capability |
| --- | --- | --- |
| `GAME_RENDER_FRAME` | One Minecraft-rendered frame. | Fabric, after the single visible connection enablement; no second prompt. |
| `GAME_WINDOW` | Operating-system capture of the Minecraft window. | Unsupported and disabled. |
| `DESKTOP` | A user-selected display/desktop. | Unsupported and disabled. |

A request for one scope must never silently capture another. The consent screen
identifies the case and expiry, states that the frame is sent to the server and
discloses the signed retention choice, and never grants a reusable permission.
Decline,
unsupported platform, expiry, capture failure, and upload failure produce an
`UNAVAILABLE` result with no cheat-risk increase. A separately published,
opt-in tournament may make evidence availability an entry requirement for that
mode, but refusal is not classified as cheating and cannot create a global ban.

### Consent and retention disclosure

Each `EVIDENCE_REQUEST` is a signed, single-use request bound to the authenticated
session, player, request ID, type, scope, and request TTL. The Fabric verifier
rejects an expired, tampered, or contradictory request before it reaches the
consent screen or can create an authorization. Old requests that omit the
retention fields explicitly mean no raw-content retention (`false`, `0`, and empty
policy/purpose). A retained request must disclose a positive duration no longer
than 24 hours, a non-empty `retention_policy_id`, and a non-empty purpose. The
signed request and the client display must agree; retention is never inferred from
the screenshot itself.

`GAME_WINDOW` and `DESKTOP` are not fallback capture modes. They remain
unsupported and disabled, produce no chunks or raw content, and return a
zero-content `UNSUPPORTED`/`DECLINED` outcome without adding risk or changing
admission. A declined, unavailable, or expired request is an availability result,
not a cheat conclusion. No screenshot, by itself, may be used as a cheat finding;
it requires provenance-aware corroboration and the normal review policy.

MCAce does not collect or retain operating-system window or desktop content.
Hidden, periodic, background, or multi-display capture is outside the product
contract. A future product would need a separately approved privacy boundary; it
would not inherit permission from this game-render-frame protocol.

## Evidence transport

Images must not be placed in the legacy single-field `EvidenceResponse.content`
transport. The bounded protocol uses:

1. `EVIDENCE_BEGIN` for immutable metadata, limits, complete-content hash, and
   chunk Merkle root;
2. ordered `EVIDENCE_CHUNK` frames with an index and per-chunk hash;
3. `EVIDENCE_COMMIT` binding the final length, hash, Merkle root, request ID,
   player, transport sequence, and session signature.

The server first sends a signed, single-use `EVIDENCE_REQUEST` with a maximum
two-minute lifetime. Every response binds the authenticated session, player,
request, evidence ID, type, and capture scope. A request receives an isolated
1,026-entry replay budget (Begin + up to 1,024 chunks + Commit), so evidence
traffic cannot consume the heartbeat replay quota. Begin and successful Commit
receive signed acknowledgements; errors are signed and request-bound. Client
uploads are paced instead of enqueueing an entire maximum transfer in one tick.

The default proxy content store discards raw image bytes after integrity and
metadata processing. Deployments that opt in to retention must use the explicit
`evidence-storage.properties` contract, an independent AES-256 key, bounded
per-item/file/total quotas, and a published retention/deletion policy. The
current controls expose bounded status/delete operations and operator deletion
audit, but no raw-image reviewer retrieval UI. Content-free audit summaries
retain the request/case, scope, outcome, dimensions, hashes, storage URI, and
operator identity.

All counts and sizes have protocol hard limits. Missing, repeated, conflicting,
oversized, expired, cross-session, or invalidly signed transfers fail without
publishing evidence. Partial content is not a reviewable evidence object.

## Policy lifecycle

Detection/disposition policy is separate from the base handshake policy. Each
document is signed and contains a stable ID, monotonic sequence, issue/effective/
expiry times, previous-document hash, rules, and explicit scope. Publication is
atomic and progresses through observe, canary, and wider rollout. Rollback is a
new higher-sequence document, never acceptance of an older sequence.

Velocity and BungeeCord evaluate the same inputs through the shared proxy policy
runtime and execute eligible session-bound events through their respective proxy
disposition executors. Paper/Folia verifies short-lived proxy admission snapshots
and may produce separately authenticated backend-context or server-authority
inputs; it neither reinterprets client disposition policy nor executes proxy
disposition events.

The shared runtime accepts only a freshly verified signed disposition document.
It enforces one policy identity, strictly increasing sequence numbers, an exact
predecessor hash, and rejects rollback or same-sequence equivocation. A missing,
malformed, expired, badly signed, or broken policy source resolves to `OBSERVE`;
it cannot escape into a platform event thread as an enforcement decision. Both
live proxy adapters now use the same bounded, atomic file source and shared
runtime. Administrators can publish bounded textproto rules through a shared,
root-signed, chained, atomic publisher, including exact-player exceptions.
Post-authentication dynamic observation completeness and controlled disposition
activation remain release gates.

## Authenticated manifest transport

Initial installed Mod, resource-pack, shader-pack, and consented configuration
observations come from the signed `AuthRequest` scope manifests. The Fabric client
also sends a distinct bounded runtime-loaded graph from
`FabricLoader.getAllMods()`. The two claims are not interchangeable: an installed
JAR can be dormant, and a nested or built-in Mod can be loaded without being a
direct `mods/` file.

Each `LoadedModEntry` contains canonical Mod ID/version plus a bounded origin kind.
A request contains at most 256 loaded identities. A direct child of
`<gameDir>/mods` may expose only its basename and is marked as
manifest-matched only when basename, Mod ID, version, size, and SHA-256 reconcile
with the signed installed `ModEntry`. Nested origins expose only their parent Mod
ID. A `PATH` origin outside the exact direct `mods/` case is classified as
`UNKNOWN`; built-in/classpath and unknown origins expose no local path. The server
rejects non-canonical order, duplicate identities, invalid origin-field
combinations, absolute/path-bearing values, and forged direct-file matches.

The signed policy can require `CLIENT_CAPABILITY_LOADED_MOD_GRAPH_V1`. The default
Velocity and BungeeCord policies do so. The client advertises it only beside a
bounded non-empty graph; the server requires sorted/unique capabilities, rejects
an empty/legacy request when the policy requires the graph, and requires every
dynamic update to retain the exact authenticated capability list. `ModEntry`
metadata must additionally bind one-to-one to the real signed `mods` scope, so an
extra or omitted installed entry fails authentication rather than extending the
policy-scoped observation set.

The same loaded graph is included in each complete signed dynamic observation.
A graph change marks the ACK-driven single-flight scheduler dirty. The first
change before any dynamic update has been accepted may trigger an immediate
attempt; after the first acceptance, later changes coalesce behind the next full
five-minute interval. The derived Mod observations expose
only server-generated `loaded`, `loaded_origin`, and
`origin_manifest_matched` selector metadata; arbitrary client metadata and signer
claims are not made available to policy selectors. These values remain
`CLIENT_REPORTED`/`LOW` and cannot create `SERVER_CONFIRMED` provenance.

Every plugin-message frame is capped at 30 KiB for the Velocity/Bungee common
transport budget. Small authentication requests retain the legacy packet. Larger
requests use individually signed `PAYLOAD_BEGIN`, ordered `PAYLOAD_CHUNK`, and
`PAYLOAD_COMMIT` envelopes with 16 KiB chunks, a 1 MiB/64-chunk total limit,
content hash, Merkle root, session ID, nonce replay protection, sequence, and a
one-minute receiver lifetime. Only one transfer may be active per session.

The proxy fixes the derived provenance to `CLIENT_REPORTED`, confidence to `LOW`,
and foundation-security status to false. Evaluation runs through a bounded
asynchronous audit queue; saturation drops audit work and never changes the
player's authentication result. Post-authentication input is limited to the
defined `ArtifactObservationUpdate`, bound to the current verified session,
aggregate root, monotonic sequence, timestamp, and transfer budget. Unknown,
stale, replayed, root-mismatched, or oversized dynamic payloads are rejected
explicitly rather than treated as processed.

Installed Fabric artifact observations are derived only from the already authorized
`mods`, `resourcepacks`, and `shaderpacks` manifests. Runtime-loaded Mod observations
are derived from the separately validated loaded graph and reconciled to those
installed entries where an exact direct-file origin exists. Both are always
`CLIENT_REPORTED` with low confidence. A bounded read of `fabric.mod.json` may
provide Mod ID/version; invalid metadata becomes `unknown`. Resource and shader
pack filenames and selected-state claims are classification inputs, never proof of
X-ray behavior.

The direct-origin SHA-256 is the installed file hash observed on disk at scan
time. It is not a JVM loaded-byte attestation and does not prove that the same
bytes are already defined or executing in memory.

## Release gates

Before any disposition affects players, tests must demonstrate:

- deterministic decisions and explanations on Velocity and BungeeCord;
- no `DENY` from a name-only or unknown-artifact match;
- allowlists cannot suppress foundation-security failures;
- rule expiry, signature failure, rollback, and malformed input fail safely;
- normal performance, accessibility, mapping, and recording Mods are included in
  false-positive fixtures;
- every limit is reversible and exposes an operator explanation;
- screenshot decline and unsupported scopes add no cheat risk;
- bounded evidence transfer rejects truncation, replay, tampering, and resource
  exhaustion without retaining partial sensitive content;
- dynamic observation refresh rejects stale, replayed, root-mismatched,
  out-of-scope, and oversized snapshots while a verified admission remains intact;
- on real Velocity and Bungee processes, an exact-policy `CLIENT_REPORTED` match
  remains advisory in both MONITOR and LIMITED_ROUTE configurations, with lobby-only
  admission and no disposition route lifecycle;
- on both real proxies, an exact-hash `ADMIN_REVIEWED` V3 authorization is durably
  journaled before execution; execution-time lifecycle/context/policy/action bindings
  hold; LIMIT/QUARANTINE use distinct reversible routes; and DENY ends only the
  current connection before a clean independent-session reconnect.

The retained 2026-08-21 commit-bound disposition evidence is
`docs/evidence/disposition-current-2026-08-21.json`: 24/24 advisory-origin
cases and 18/18 trusted administrator cases passed with Execute and ReportOnly.
The August 13 aggregates are older retained history; neither historical set is a
substitute for current-tree release evidence.

The defensive detection regression record is
`docs/evidence/anti-cheat-detection-2026-08-21.json`. It covers scoped integrity,
artifact-feature neutrality, replay/tamper/expiry rejection, and multi-provider
behavior correlation. It does not claim a production cheat precision/recall rate;
the licensed Vulcan runtime event remains an explicit pending gate.
For reproducible controlled-fixture checks, use
`scripts/anticheat-fixture-smoke.ps1 -Execute` with explicit, locally reviewed
Meteor and Xray-pack paths plus SHA-256 values. The wrapper runs the bounded
metadata/classification JUnit fixture in a temporary directory, requires JDK 21,
and records `CONTROLLED_LAB_FIXTURE_METADATA_AND_SERVER_CORRELATION`; the fixture
has no executable entrypoint and no third-party code is launched. The retained
commit-bound Helio witness ran the same client-observation plus independent same-session
server-signal correlation for 1.21.11, 26.1.2, and 26.2, with six
`SERVER_CONFIRMED/CONFIRMED` upgrades and explicit wrong-session/expired-window
negative boundaries, on tested source `d835f42…` (the later `56ecad8…` commit only
adds docs/evidence). See the retained sanitized
[`helio-2026-08-25-anticheat-sync-current.json`](evidence/helio-2026-08-25-anticheat-sync-current.json)
and its raw reports under `docs/evidence/helio/anticheat-sync-r6/`. Revalidate a
saved record with `-ReportOnly -ReportPath <report.json> -ExpectedReportSha256 <sha256>`.
A separate bounded real-client smoke has now loaded the supplied Meteor JAR in a
disposable 1.21.11 Fabric client and activated the selected Spectator Xray pack;
the client reached resource reload and Meteor initialization, but never connected
to a server and did not activate a cheat feature. This is a client discovery and
resource-loading result only, not evidence of server-side detection, a
`SERVER_CONFIRMED` event, or a kick/deny outcome. The run was not network-isolated
because the normal client attempted account/Realms requests, so it must not be
described as a safe third-party sandbox or as an effectiveness benchmark.
The remaining distinct gates are a release-grade real-process `SERVER_CONFIRMED`
artifact/behavior authority witness and the Federation V5 source-to-target handoff
with the sole source-side visible enablement decision; the target must not open a
second prompt. The Federation V5 parser/static contract passes for its exact
eight-file package: report, binding, commit, GUI signing request, decoded PNG,
runtime ledger, externally signed `MCACE_VISIBLE_GUI_ATTESTATION_V3`, and externally
signed post-run receipt. The two signatures must chain to different approved roots,
and no independently signed real visible-session handoff PASS exists yet.
