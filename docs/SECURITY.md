# Security model

## Defensive objective

MCAce raises the cost of client modification and produces reviewable evidence. It
does not claim that a user-mode client can prove the absence of all cheats.

## Technique classes and observables

| Technique | Relevant MCAce signal | Required corroboration |
| --- | --- | --- |
| Modified mod/assets/config | Signed manifest mismatch | Server policy/build records |
| Protocol replay/forgery | Nonce reuse, bad signature, stale timestamp | Server session log |
| Injection/internal hook | No reliable Mod-only integrity signal | Behavior telemetry/build baseline |
| Input automation | None from integrity alone | Longitudinal server behavior detection |
| External/kernel/DMA | Client may have no reliable signal | Server authority and behavior systems |

## Decision policy

- A single client anomaly creates a risk event; it does not create a ban.
- High-impact action requires corroboration, operator review, and an appeal path.
- Risk explanations retain the contributing event IDs and policy version.
- Missing telemetry is distinct from confirmed malicious telemetry.
- Policies must be replay-tested against known-good and controlled anomalous sessions.

### `v0.0.1` release-security status

Evidence inventory audited August 26, 2026. These are terminal release gates,
not predictions derived from caller-supplied booleans:

| Gate | Status | Required release proof |
| --- | --- | --- |
| Matrix | **PENDING — Matrix V4** | Exactly twelve raw process reports, raw manifest, exact protected V4 bundle/server-JAR bindings, and an unexpired detached receipt from an externally controlled supervisor under an out-of-band approved pin. Historical Matrix V1 12/12 and every V2/V3 document are diagnostic only. |
| Visible GUI / Federation | **PENDING — Federation V5** | Exactly one visible, connection-bound `Enable MCAce` human approval for the entire release acceptance, followed by the real V5 source-to-target handoff and independently signed post-run receipt. The other two Fabric targets receive UI compatibility smoke, not additional approvals. |
| Vulcan | **PENDING — Vulcan V3** | A genuine, non-synthetic licensed-provider event bound to the exact release artifacts and an externally pinned supervisor receipt. Vulcan V2 remains diagnostic only. |
| Production authority | **PENDING — Authority V4** | Actual signed grant/observation frame bytes, raw provider/Paper/proxy/process/journal ledgers, recomputed commitments, exact release JARs, and an external-supervisor receipt/index. |
| Protected release CI | **PENDING — protected V4 `main`/tag CI** | The canonical artifact-source marker, exact `MCACE_RELEASE_BUNDLE_V4`, every native evidence gate above, and fail-closed readiness must agree at the protected commit and tag. |

### Signed disposition execution boundary

Velocity and BungeeCord now have separate bounded, session-bound, idempotent
executors for signed disposition events. `MONITOR` is the default and does not
execute high-impact actions. NOTICE, WARN, and CHALLENGE are sanitized hints;
CHALLENGE does not imply that a screenshot was requested or sent. LIMIT and
QUARANTINE execute only in explicit `LIMITED_ROUTE` mode with two different,
registered targets: `disposition.limited.server` for LIMIT and
`disposition.quarantine.server` for QUARANTINE. A missing, unregistered, or shared
target fails safely to effective `MONITOR`; primary handshakes remain available and
LIMIT, QUARANTINE, and DENY do not execute. With a valid pair, DENY disconnects
the current connection only; it never bans the player, crosses a reconnect
boundary, imposes later punishment, or requests evidence automatically.

Execution fails closed when the policy is malformed, expired, revoked, or has no
winning rule; when the event is late or bound to a stale session; when the current
admission is not `VERIFIED`; or when a high-impact event lacks a durable trusted
authorization ID and its session, review-input, and execution-context commitments.
Within one physical-lifecycle and policy-atomic boundary immediately before action,
the proxy revalidates the exact current session, `VERIFIED` admission, exact context
commitment, active policy identity/status/expiry, current winning rule, and that
`rule.action` equals the event action. Duplicate deliveries cannot repeat an action, and bounded
queue/cache limits prevent an untrusted event stream from creating unbounded state.
Evidence refusal, unsupported scope, decline, expiry, transfer failure, or missing
content is not a disposition trigger. Client evidence remains `CLIENT_REPORTED` and
cannot independently justify punishment.

The retained August 21 three-target Velocity/Bungee advisory-origin aggregate
passed 24/24 and recorded that all exact-policy client matches, including DENY on
both proxies, remained on lobby with no route lifecycle or connection close. Its
trusted V3 aggregate passed 18/18 `ADMIN_REVIEWED` exact-hash actions across
1.21.11, 26.1.2, and 26.2. The sanitized committed chains are in
`docs/evidence/disposition-current-2026-08-21.json`; the August 13 files remain
retained history.
The command carries no action; the active signed policy selects it, and the
content-free authorization journal is forced to disk before the session-bound event
is queued. Both proxies completed distinct LIMIT and QUARANTINE routes. DENY closed
only the current connection, and the same offline identity then established an
independent verified lobby session. The trusted aggregate declares
`authorization_contract=UUID_CONTEXT_COMMITMENT_V3` and confirms strict 16-column
V3 journal persistence before every execution.
Neither aggregate claims a real-process `SERVER_CONFIRMED` artifact source or Fabric
GUI coverage.

### Server-confirmed issuance journal boundary

The default-disabled, MONITOR-only `SERVER_CONFIRMED` authority path now has
configuration, provider correlation, proxy grant issuance, Paper/Folia signing and
journaling, platform channel registration, and proxy-side observation verification
on Paper/Folia, Velocity, and BungeeCord. It remains disconnected from disposition
authorization and every automatic action executor. No verified authority frame can
select or execute LIMIT, QUARANTINE, DENY, kick, or ban.

The journal abstraction and file implementation enforce durable-before-return
issuance. Every implementation defines `lastSequence`; there is no default-zero
recovery. An operator must precreate its directory and regular file, write the exact
fixed versioned header, and restrict ownership and ACLs before startup. Runtime has
no create or initialize path. A public read-only preflight returns the exact required
header bytes and validates the supplied path without creating or modifying the
directory, file, header, or records.

The journal keeps one read/write handle and an exclusive file lock for its full
lifetime. On the supported Windows/OpenJDK 21 path it also requests
`NOSHARE_DELETE` and `NOSHARE_WRITE` and fails closed when they are unavailable.
On non-Windows it requires a non-null stable filesystem `fileKey`. Both paths
reject links and special files and repeat no-follow checks for the journal and
its ancestors. Each candidate is decoded through the same handle, appended,
forced with `force(true)`, and decoded again through that handle before canonical
path bytes and identity are rechecked. An I/O, path-identity, force, or post-force
verification failure returns no token and latches both the journal and issuer
unusable until close/reopen. Semantic rejection before journal I/O, including a
grant/key mismatch, returns no token without poisoning the issuer.

Sequence ownership is durable rather than volatile.
`DurableServerAuthorityIssuer.recover(VerifiedGrant)` reads the exact lifecycle's
last journal sequence and returns a non-externally-constructible
`RecoveredServerAuthoritySequence`; callers cannot seed restart state with an
untyped number. Issuance allocates `last + 1`, signs and appends it, and returns a
durable token only after verification. That token binds the exact verified grant,
lifecycle, backend key, and observation/issuance/expiry window. There is no
separate in-memory allocator to advance before append. Paper prepare returns a
unique lease capability, commit requires its matching durable token, and abort
releases the pending issuance so a fresh prepare can retry. The disabled lifecycle
retains nothing.

The package-private Paper coordinator preserves the exact ordering: request/lease/
grant precheck, journal-derived next sequence and `force(true)`, then exact lifecycle
commit. It returns no capability until commit; the raw frame accessor remains
package-private to the core authority package and is not available to Paper.
Durable-sequence drift removes the lifecycle and requires fresh typed recovery.
Uncertain I/O, runtime uncertainty, abort failure, or failure after the durable
append poisons the coordinator and prevents retry of an already advanced sequence.

The retained August 20 JDK 21 offline authority selections covered 8 suites and 51
tests with zero failures/errors and one host-capability symlink skip; the retained
root/modern aggregate recorded 171 suites and 755 tests. These are historical
development witnesses, not genuine production-process evidence. The runtime wiring
does not promote unit or fixture results: the Authority release gate remains
**PENDING — Authority V4** until actual signed frame bytes and raw ledgers are
externally supervised, revalidated, cross-bound to the exact protected V4 bundle,
and published as a non-replayed V4 index. See
[`SERVER_CONFIRMED_AUTHORITY.md`](SERVER_CONFIRMED_AUTHORITY.md) and
[`PRODUCTION_AUTHORITY_PROVISIONING.md`](PRODUCTION_AUTHORITY_PROVISIONING.md).

This narrows replacement and uncertain-write failures during runtime; it is not
a Java SE storage-immutability claim. The Windows no-share flags are OpenJDK
extensions, filesystem `fileKey` quality is provider-dependent, and pure JDK code
cannot verify that host ACLs remain correct, defeat a local administrator or
privileged storage actor, or prove that bytes were not changed after a token was
returned. The service directory therefore requires least-privilege ACLs,
ownership/change monitoring, backups, and independently protected audit or
immutable storage when post-return tamper evidence is required.

## Build supply-chain boundary

The retained August 20 Windows A/D strict-offline runs each completed 118/118 tasks with
JDK 21.0.7+6 for the root, isolated JDK 25.0.3+9 for modern Fabric, and Gradle
9.6.1. Root results were 147 suites / 681 tests / 0 failures / 0 errors / 28
skipped; modern results were 24 / 74 / 0 / 0 / 0; combined results were
171 / 755 / 0 / 0 / 28. Both exact-eight LOCAL bundles were byte-identical.
`docs/evidence/local-build-2026-08-20.json` retains the sanitized result;
`build/` remains mutable diagnostics.

Dependency-verification exceptions remain narrow: 47 exact root Loom-local trust
entries and two exact modern named-Minecraft trust entries. There is no broad
group trust; POMs, mappings, upstream modules, Fabric dependencies, and native
`protoc` artifacts remain SHA-256 verified. The local manifest records
`source_commit=LOCAL_UNSPECIFIED` and `release_identity=false`.

The retained August 20 Linux run `cb6dc44ddad744b5a20dc2986c0a6d70` passed strict
offline network-none verification with exact JDK 21.0.7+6/JDK 25.0.3+9, 171
suites / 755 tests / 0 failures / 0 errors / 33 environment-conditioned skips,
an unchanged 735-file source manifest, exact-eight stream-byte parity with
Windows A/D, and zero residual containers/run-scoped Java processes at 0/30/60
seconds. The external witness SHA-256 is
`de6d82fedace1c7b961ba9879b6e924df1bc8a1d085b851134194bac91d44b48`.
The old JDK-21,
52-rule, four-deployable exact-six run and the superseded pre-fix exact-eight run
remain historical. Protected `MCACE_RELEASE_BUNDLE_V4` exact-commit `main`/tag CI
remains **PENDING**.

## Audit provenance and availability

- Every persisted observation retains its source, including `SERVER_CONFIRMED`,
  `CLIENT_REPORTED`, `INFERRED`, `ADMIN_REVIEWED`, or unavailable/missing state;
  storage does not promote a client claim into a server-confirmed fact.
- Risk events, evidence metadata, revocations, and operator audit are append-only.
  Evidence metadata has a globally ordered SHA-256 predecessor chain and Ed25519
  signature; revocations have an ordered sequence and domain-separated signature.
- Review and appeal snapshots are mutable only through version-checked state
  transitions. Each transition and its operator audit record are append-only and
  commit atomically with the new snapshot and player notification. Terminal
  decisions cannot be reopened.
- Risk-policy releases, rollout events, per-event evaluations, and reviewed
  feedback are append-only. Database triggers enforce complete weight sets,
  rollout ordering, one active candidate, and feedback/outcome consistency.
- PostgreSQL unavailability is an infrastructure incident, not player risk. The
  bounded audit queue reports failures without delaying or changing admission.
- PostgreSQL, Cloud, and the web portal are optional repository integrations, not
  prerequisites for the primary Fabric/proxy/backend path. Their presence does
  not mean that a production raw-image reviewer retrieval UI is implemented.
- A database administrator can still disable triggers or destroy rows. Chain
  verification exposes inconsistent surviving data. Periodic signed external
  anchors now commit the evidence head, ordered revocation feed, operator audit,
  and preceding anchor; an independently retained ledger can therefore expose
  rollback or deletion after publication. Backups, retention policy, ledger
  monitoring, and object-storage immutability remain operational requirements.

### Three-version process security gate

The retained Helio aggregate at
`docs/evidence/server-version-process-matrix-2026-08-25-f404971.json` and its
adjacent report/binding/commit use Matrix V1. They record 12/12 for exact source
`f404971e6e9a9ac1d30e5cf4e2692750aa83f1b1`: Paper 6/6, Folia 6/6, Velocity
6/6, Bungee 6/6, ten STABLE cases, two Folia 26.2 build-6 BETA cases, and zero
cleanup residue. This is historical loopback diagnostic evidence only. It has no
twelve-file immutable raw set, protected V4 bundle cross-binding, or externally
signed supervisor receipt. Matrix V2 and V3 are likewise terminally ineligible for
release.

[Matrix V4](SERVER_VERSION_MATRIX_EVIDENCE_V4.md) is the first release-capable
schema. `scripts/server-version-process-matrix.ps1 -Execute` must run from the
exact clean artifact source with an exact protected `MCACE_RELEASE_BUNDLE_V4`, an
out-of-repository RSA public root, a separately controlled supervisor exchange,
and the protected process pin
`MCACE_RELEASE_APPROVED_MATRIX_SUPERVISOR_TRUST_ROOT_SHA256`. The producer freezes
exactly twelve raw reports and their manifest, prints a randomized signing request,
and waits for the independent supervisor to verify the run and atomically return an
unexpired detached receipt. Then run `-ReportOnly` and publish the complete package
with `scripts/publish-server-version-matrix-evidence.ps1`; publisher and readiness
repeat bounded no-follow byte/schema/hash, process-incarnation/exit/cleanup, replay,
source/artifact-commit, protected-bundle, and server-JAR validation. The complete
minimal command sequence is in
[`RELEASE_GATES.md`](RELEASE_GATES.md#authoritative-matrix-v4-process-commands).
No release-eligible Matrix V4 index is retained, so this gate is **PENDING**.

The raw peer is bounded, offline, loopback-only test tooling. It is not a Fabric
client and cannot provide GUI consent, online-mode identity, or public-network
proof. Shadow context cannot invoke admission, routing, disconnect, punishment,
evidence, or disposition. The former Paper 1.21.1, BungeeCord 2028, and Folia
1.21.4-6 wrapper records are also historical and must not be cited as `v0.0.1`
1.21.11/26.x release evidence.

The separate per-target Fabric wrapper has passed server-only startup and asset
prewarm for all three targets. Release acceptance still requires **exactly one**
visible, connection-bound `Enable MCAce` human approval on one selected real
connection. That single decision is consumed by the Federation V5 source-to-target
handoff. The other two Fabric versions receive UI compatibility/visual smoke only;
they are not second or third approvals and cannot promote consent evidence. Close,
decline, timeout, or missing/invalid signed evidence leaves MCAce disabled. This
one-witness release rule does not create reusable consent for future connections:
runtime authorization remains connection-bound and is cleared as described below.

## Privacy boundary
Allowed roots are the active Minecraft instance's `mods`, `resourcepacks`, and
`shaderpacks`, plus explicit relative files named by the already verified signed
policy. The built-in client pre-consents to no file. It shows every requested
path in a paged prompt and, if accepted, keeps the exact authorization in memory
for the current connection only so signed manifest refreshes may re-read it.
Disconnect, a replacement challenge, or shutdown clears the authorization.
Only relative path, byte size, and SHA-256 are sent; raw file bytes are not
uploaded. Symlinks are not followed. The scanner enforces file-count, file-size,
extension, path-containment, and policy scope ceilings.

Forbidden collection includes unrelated files, keystrokes, camera, microphone,
browser data, private documents, hidden persistence, and kernel-level inspection.
The Fabric build also has a bytecode privacy regression gate that rejects links to
AWT Robot/screen capture, JNA/User32, process enumeration, keyboard hooks, and
Windows module enumeration. This does not replace code review, but makes an
accidental desktop/process inspection dependency a test failure.

Screenshot permission is request- and scope-specific. Fabric supports one
`GAME_RENDER_FRAME` after the player selects `Enable MCAce` on the connection-level
visible prompt; no second evidence prompt is rendered.
The capture path uses Minecraft's framebuffer and in-memory PNG encoding; it
does not call a desktop/window API or write a client-side screenshot file.
  `GAME_WINDOW` and `DESKTOP` are disabled and return zero-content outcomes.
  Closing, declining, ignoring, expiry, encoding failure, or upload failure is an
  availability result, never a cheat finding or automatic punishment. Uploads are
  bounded to 4,000,000 pixels, 16 MiB, 1,024 chunks, and 30 KiB signed transport
  frames. Raw server-side retention is disabled by the default discard store. A
  legacy request with no retention fields means false/zero/empty; an opt-in
  retained request is bounded to 24 hours and must disclose its policy ID and
  purpose. The client verifies these fields before showing or authorizing consent.

Local evidence review is a separate opt-in loopback capability, never a player
feature. It starts only with an actual review-capable retained store, binds only
`127.0.0.1`, and issues short-lived single-use URLs only to the proxy console.
Player command sources are rejected even when otherwise permitted. Review URLs,
keys, paths, and raw content never enter Minecraft chat, admission, routing, or
punishment logic; startup/configuration failure leaves review disabled.

### Optional raw-evidence storage

- A generated `evidence-storage.properties` uses `enabled=false`. Disabled mode
  uses the discard store and does not write raw evidence.
- Enabling storage requires both `enabled=true` and
  `client-consent-contract-confirmed=true`, plus positive `retention-seconds`
  (at most 86,400), non-empty `retention-policy-id` and `retention-purpose`, and
  an independent 32-byte AES key at the configured `key` path. The key is not the
  Ed25519 server identity or policy key.
- The default quotas are 16 MiB per object, 256 files, and 256 MiB total. The
  store rejects quota overflow, invalid metadata binding, unauthenticated
  ciphertext, and expired content. A proxy scheduler performs a bounded sweep of
  at most 32 expired files per minute.
- Operators use `/mcaceevidence storage status` for bounded counts/limits and
  `/mcaceevidence storage delete <evidence-id> <reason>` for deletion. Delete
  operations append an operator audit record; status does not expose raw bytes,
  keys, or filesystem paths. There is no raw-image reviewer retrieval UI yet.
- The store rejects symlink roots/files and uses bounded, atomic file operations,
  but ordinary Java `Path` operations cannot make a Windows host immune to a
  privileged directory replacement or weak NTFS ACLs. Put the store and key in a
  dedicated directory, grant access only to the proxy service account and
  approved operators, deny ordinary players/write-capable plugins, and monitor
  ACL and directory changes. Treat this as a residual deployment risk.

## Cryptography

- Ed25519 signs protocol envelopes.
- SHA-256 identifies files and manifest roots.
- CRC32C is only an early corruption check, never an authenticity mechanism.
- Nonces are single-use within a bounded server replay window. The replay cache
  has both per-session and global capacity limits: one authenticated client
  cannot consume another session's quota, while aggregate memory remains
  bounded. New nonce claims fail closed when the applicable quota is full.
- Production keys require rotation, revocation, secure-at-rest storage, and audit.
- Velocity can dispatch adjacent plugin-message events on different task workers.
  The coordinator therefore retains at most one same-session direct `AUTH_REQUEST`
  that arrives before its wire-preceding `CLIENT_HELLO`. It does not authenticate
  or publish state at defer time. After `CLIENT_HELLO` establishes the client key,
  the retained envelope must still pass its signature, nonce, session, policy,
  manifest, and scope checks. A duplicate early request or any other early packet
  remains a server-confirmed protocol violation; forged deferred requests fail
  when identification completes.

### Heartbeat session contract

- Heartbeats are individually signed envelopes bound to the authenticated session
  ID. The receiver enforces the 30 KiB proxy frame budget, envelope timestamp,
  signature, nonce replay guard, and `HEARTBEAT` packet type before evaluating
  the payload.
- The authenticated manifest root, aggregate root, policy sequence, and policy
  SHA-256 are fixed at session creation and must match every heartbeat. Sequence
  values are positive and strictly increasing; gaps are allowed so one dropped
  packet does not poison recovery. Invalid packets never advance the sequence or
  freshness anchor.
- The receiver accepts only `VERIFIED` as the client-reported heartbeat status;
  `TRUSTED` and `SECURE` are not client-authoritative levels. `current_server`
  is the policy-controlled server ID, not the player's address; it must be
  non-blank, contain no ISO control characters, and be no longer than 128
  characters.
- The first heartbeat receives the same grace period as an authenticated session:
  age `<= 60s` is `ACTIVE`, `> 60s` through `90s` is `STALE`, and age `> 90s` is
  `MISSING`. A valid later heartbeat returns the transport state to `ACTIVE`.
  Wall-clock rollback cannot create recovery without a valid new heartbeat, and
  elapsed time overflow fails closed as `MISSING`. These health values are
  monitor-only by default. An operator may explicitly enable the proxy-local
  `heartbeat.missing.*` control, which requires 2–300 consecutive one-second
  `MISSING` polls and can only send a NOTICE or, with effective `LIMITED_ROUTE`,
  route the current session to the configured limited server. Effective routing
  requires different registered canonical limited and quarantine targets; an
  invalid pair remains `MONITOR`. `STALE` never acts. It never changes risk,
  admission, or trust; never disconnects, bans, permanently punishes, or requests
  evidence; and cannot recover from replayed or invalid packets. A later valid
  heartbeat clears the temporary control and may notify the player. MCAce never
  guesses or forces a return to an unknown prior backend server.

- Opt-in encrypted evidence storage writes a self-describing v2 AES-256-GCM
  envelope: complete bounded metadata and raw bytes are encrypted together, and
  payload AAD binds the evidence UUID and expiry. Review reads accept only v2;
  absence returns no artifact, while expiry, wrong keys, tampering, malformed
  metadata, or changed files fail closed. Legacy v1 records remain available only
  through the existing caller-supplied-metadata read path during migration.
  transport availability signals only, not cheat findings or punishment
  instructions.
- `AuthResult.expires_at` limits the freshness of the signed admission result at
  receipt time; it is not a heartbeat lease. Once that current signed result has
  established the session, independently signed and session-bound heartbeats may
  continue until disconnect or explicit session removal.
- `AUTH_RESULT.expires_at_epoch_ms` is a signed two-minute admission-result
  freshness bound, not the heartbeat session lease. The client rejects an
  already-expired signed result, then continues independently signed heartbeats
  for the live authenticated transport; disconnect/removal is what ends that
  session path. The replay cache is bounded globally at 100,000 entries and at
  128 entries per session, so a single valid client key cannot consume all
  players' nonce capacity.

### Cloud authentication and ingestion

- Only public keys listed in the Cloud server registry can request a challenge.
- Challenges expire after 30 seconds, are bounded, and are consumed before proof
  verification. PostgreSQL serializes cross-instance quotas and atomically burns
  a challenge with `DELETE ... RETURNING`, so issue/exchange may land on different
  instances while concurrent replay still has one winner. Success issues a
  five-minute scoped Ed25519-signed token.
- Cloud authentication-token keys are separate from audit keys. Evidence and
  revocation signatures use separate domain prefixes under the audit key.
  External anchor signatures use a third `mcace-audit-anchor-signature-v1`
  domain and chain each anchor to its predecessor.
- API JSON is strict and bounded. Duplicate/unknown fields, excessive bodies,
  missing required primitives, and out-of-window timestamps fail validation.
- Risk-event callers cannot submit weights; Cloud assigns the configured policy
  weight and retains the submitted observation origin.
- Revocation writes require an operator scope, review ticket, and HTTPS appeal
  URL. The result is a signed distribution record, not an automatic punishment.
- Review and appeal writes use separate scopes, strict state machines, and
  optimistic versions. The authenticated actor is a trusted service identity;
  Minecraft clients cannot directly manufacture operator decisions.
- Policy authoring, feedback, and metrics use separate scopes. Stable cohort
  assignment binds a player to an immutable policy ID; SHADOW never assigns a
  candidate weight, and every evaluation records both baseline and candidate.
- A false-positive label is not accepted from raw client telemetry. It must be
  linked to the same player's reviewed case and a no-action or granted-appeal
  outcome. Metrics are observational and never execute punishment.
- Plain HTTP binds to loopback by default. Production exposure requires TLS,
  rate limiting, and request-size enforcement at a trusted local proxy as well.

### Web dashboard and appeal portal

- Only a trusted SSO bridge may hold `WEB_OPERATOR_SESSION_WRITE`; only a service
  that already authenticated the Minecraft player may hold
  `WEB_PLAYER_SESSION_WRITE`. Neither scope grants dashboard or player data access
  through a bearer token.
- The bridge receives a two-minute handoff code in an HTTPS URL fragment. Cloud
  stores only its domain-separated SHA-256 hash and atomically deletes the row
  before checking the secret, so success, failure, and replay all burn the code.
- Successful exchange creates an eight-hour opaque session. PostgreSQL stores only
  the session-secret hash; the browser receives a `__Host-` cookie with `Secure`,
  `HttpOnly`, `SameSite=Strict`, and `Path=/` attributes.
- Operator sessions carry explicit Viewer, Reviewer, and Policy Admin roles.
  Player sessions carry only `PLAYER`, bind to exactly one UUID, and all player
  timeline, appeal, notification, and read-receipt operations derive that UUID
  from the session rather than request JSON or a URL parameter.
- Every browser mutation requires the configured HTTPS `Origin` plus a separate
  double-submit CSRF cookie/header. Pages use a same-origin-only CSP, reject
  framing and referrers, disable unrelated browser permissions, and insert API
  content as text rather than executable markup.

### Current key handling

- Velocity creates a persistent Ed25519 identity on first start and refuses a
  partial or mismatched public/private key pair.
- The private key is never sent to clients. POSIX deployments restrict it to the
  owner where supported; operators must protect the plugin directory on Windows.
- Fabric requires an exact server-address pin or an explicit `default` pin.
- Velocity keeps the server identity as the pinned root and stores a separate
  delegated policy signing key. The root signs a bounded trust statement; the
  delegated key signs 24-hour operational policies.
- Delegated keys are valid for 14 days and rotate within their last two days. A
  higher-sequence root statement removes and explicitly revokes the old key.
- Fabric caches the highest verified policy and trust sequences per server address
  and rejects rollback, same-sequence equivocation, unauthorized signers, revoked
  signers, or policies extending beyond their delegated validity window.
- Root and delegated private keys remain online in the current Velocity milestone.
  An offline-root or external signer deployment is a later hardening option.

### Backend admission channel

- Paper pins the same Velocity root public key separately; it never learns either
  private key and refuses to enable its MCAce integration without the pin.
- Velocity signs every `mcace:admission` snapshot. Paper validates the envelope,
  packet type, 15-second expiry, nonce replay window, carrier UUID, payload UUID,
  increasing transport sequence, evaluation time, reason total, and enum values.
- Velocity refreshes every five seconds. Paper removes state when refresh stops,
  the player quits, or the signed TTL expires, preventing indefinite reuse of a
  one-time `VERIFIED` result.
- Invalid backend messages do not overwrite an accepted snapshot and do not cause
  a ban. A backend restart clears volatile replay watermarks, but proxy restart
  disconnects the player carrier; signed TTL and envelope freshness bound the
  residual replay window.

### Backend context shadow channel

- Paper/Folia reads world and game mode only through the Bukkit API on the owning player/entity
  thread. It publishes after accepting a signed admission snapshot and after world or game-mode
  changes. No desktop, window, process, input, or raw file data is present.
- The `mcace:context` payload deliberately omits backend identity. Velocity/Bungee derive it from
  the event-supplied backend connection and require that connection to carry the target player. The
  check does not wait for an eventually consistent current-server pointer; exact runtime
  backend/session/admission bindings still fail closed. A player/client source is consumed without
  parsing and can never enter the context runtime. Fabric advertises the S2C channel only as a
  transport route for the backend return and never parses, trusts, or acts on the payload.
- Each report must match the current player UUID, authenticated session, exact current backend,
  latest proxy-signed admission transport sequence, increasing report sequence, canonical world and
  game-mode vocabulary, 4 KiB frame limit, and two-minute freshness/binding windows.
- Accepted reports re-evaluate only the latest bounded in-memory authenticated manifest on a
  bounded audit worker. The result contains aggregate action/issue counts and context labels only;
  the runtime has no admission, routing, disconnect, punishment, evidence, or disposition-event
  callback. Queue rejection and invalid reports leave all player state unchanged.
- A compromised backend remains able to lie about its own world or game mode. Shadow-only rollout
  is therefore mandatory until independent production observations and operator review justify a
  narrower authority model; backend context is not automatically promoted to artifact provenance.

## Current detection hypothesis

A valid handshake confirms that the peer possessed the ephemeral private key and
answered a fresh challenge using a client that can produce the configured protocol
and manifest. It does not confirm absence of injection, external memory tools,
automation, kernel/DMA access, or a patched scanner. Those require independent
server behavior signals. MCAce does not introduce an Agent or claim Mod-only
visibility into unrelated processes, kernel state, or external hardware.

### Proprietary anti-cheat compatibility preflight

The Vulcan adapter consumes a narrow reflective event contract and never bundles
the proprietary API. `scripts/vulcan-licensed-api-compatibility-smoke.ps1`
accepts only an explicitly supplied direct local JAR. UNC and mapped-network paths
are rejected, as are artifact or parent reparse points. A `FileStream` opened with
read-only sharing remains held across the inspection; size and SHA-256 are
calculated from that same handle before and after the gate. The script invokes only
an already installed, locally marked Gradle distribution directly with `--offline`,
bypassing the wrapper downloader. It hashes the complete installed Gradle tree with
file/directory counts before and after execution and rejects any enumerated reparse
point. It also requires the Gradle-selected JVM to be Java 21 and rejects unbound JVM/
Gradle option environment variables, `ORG_GRADLE_PROJECT_*`, user Gradle properties,
and user init scripts. The gate records no artifact path, copies or extracts no
classes, and emits only an exact-schema sanitized hash, size, declared version,
selected public accessor names, fixed coverage booleans, and limitation enum.

The absolute JAR path is present in the local Gradle/JVM command line while the
preflight runs, even though neither retained JSON file records it. Operators must
therefore treat local process-list access as part of the licensed environment's
trust boundary.

The adjacent path-free binding sidecar records the digest of the read-locked report,
a deterministic manifest over every repository file except `.git`, `.gradle`, and
directories named `build`, the complete installed Gradle-tree identity, and the
selected Java 21 executable identity. Both JSON artifacts reject unknown properties.
Execution and report-only validation reject network/reparse evidence paths, lock and
rehash both files, reject an old unbound or source/runtime-mismatched report, and
apply a bounded freshness window. These controls detect accidental substitution and
stale evidence; they do not authenticate the publisher, prove a license, or defend
against an administrator who can rewrite both local evidence files and source.

The held PowerShell handle and equality with the Java-generated artifact hash bind
the outcome to artifact content. The Java inspector still opens the validated path
independently and the wrapper does not claim a Windows volume/file-ID proof across
those opens. Closing that narrower identity gap requires changing the gate API,
not merely this local wrapper.
Structural compatibility is not runtime proof: Paper plugin enablement and real
behavior-event delivery remain false in the preflight report and must be verified
separately with an operator-owned license environment. Missing or incompatible
Vulcan disables only that adapter; it cannot change MCAce admission, risk,
disposition, evidence, or punishment.

The retained [Vulcan 2.9.0 preflight evidence](evidence/vulcan-licensed-api-preflight-2026-08-13.json)
records a successful exact-hash structural API inspection and ReportOnly binding
revalidation that were contemporaneous with its bound historical source snapshot.
It deliberately retains no artifact path, artifact bytes, or run identifier.
Reuse against any later source fails closed on source-manifest drift, so every
candidate needs a fresh structural preflight and binding revalidation. The retained
record's false Paper-enable/event coverage is normative: it is not compatibility
evidence for the eventual artifact source, Paper runtime proof, or release proof.

The repository also contains an unexecuted, default-deny
`scripts/vulcan-paper-enablement-smoke.ps1` harness. It cannot start without the
  reviewed Vulcan/Paper/MCAce hashes, an explicit temporary Paper-remap permission,
  an independently reviewed prepared-runtime manifest SHA-256,
and `-NetworkPolicy DenyAll` plus an operator attestation that a deny-all
OS/network boundary has already been enforced. The script deliberately records
`network_isolation_os_verified_by_script=false`; the attestation is not technical
proof of isolation. On a successful run it would remove the isolated Paper root
and retain only a sanitized enablement report. Such a report could prove Paper
process coverage, licensed-plugin enablement, and MCAce listener registration,
but its schema fixes real behavior-event delivery false. A genuine bounded Vulcan
trigger through the registered listener remains a separate authorized gate and
must not be replaced by an MCAce-constructed event or test observer.
`scripts/vulcan-genuine-event-smoke.ps1` has two deliberately separate contracts.
Its V2 path remains a content-free diagnostic: it rejects synthetic dispatch and
requires an externally triggered expected-player `SERVER_CONFIRMED`
`vulcan-adapter` delivery, but operator attestations cannot promote the resulting
V2 triplet. Its `-ReleaseGradeV3` path is the implemented release-grade producer.
That path loads the reviewed licensed Vulcan JAR with the exact upstream Paper and
MCAce Paper JARs, accepts only the real registered Bukkit callback, and writes an
append-only provenance ledger binding plugin/listener/event/accessor code sources,
callback thread and sequence, provider/check/violation commitments, and Paper
process incarnation. It freezes the raw risk event, report, binding and ledger,
emits a canonical repository-external signing request, and accepts only an
independently signed RSA supervisor receipt under an out-of-band approved root.
The exact V3 package contains seven files: report, binding, commit, signing request,
supervisor receipt, raw risk event, and callback provenance ledger. Producer and
publisher accept the receipt inside its exchange window; later readiness verifies
the immutable signature and historical ordering without wall-clock expiry.

Release status is **PENDING — Vulcan V3 evidence, not implementation**. No reviewed
licensed Vulcan JAR, non-fixture callback capture, external-supervisor receipt, or
release-eligible V3 index is retained by the repository. Structural preflight,
enablement, every V2 triplet, and every fixture remain diagnostic and cannot close
the gate. MCAce neither downloads nor redistributes the licensed Vulcan artifact.

## Cross-network federation boundary

The versioned federation protocol and attack corpus are implemented; proxy/Fabric
runtime release gates remain disabled by default. The normative threat model,
four-message state machine, privacy contract, residual risks, and release matrix
are in `docs/FEDERATION.md`.

Federation is client-carried. It has no source-target control channel, HTTP or
socket service, callback, token broker, Cloud dependency, target-initiated source
request, or live redemption. The one visible connection-level `Enable MCAce`
screen states that the future target is not yet known and permits the source to
select at most one operator-pinned target without a second prompt. A human-origin
authorization atomically reserves one exact source assertion; a second distinct
assertion and every inherited target export are rejected. The source signs a grant,
and Fabric retains that grant plus its short-lived source-session key only
in bounded memory. Source and target identity keys are independently pinned in
the two operators' offline configurations and are bound into consent/assertion.
Equal source/target fingerprints are rejected by the protocol, and runtime
startup/reload rejects a peer pin equal to the local identity.

After receiving a complete grant, Fabric may carry it across source disconnect
or source proxy restart until its signed expiry of at most five minutes. Fabric
computes `H_A = SHA-256(SignedFederationAssertion.toByteArray())`; the target must
then independently authenticate the player locally as `VERIFIED` using the same
short-lived client key **and** the exact assertion identity. The client-signed
`ClientHello` and `AuthRequest` each carry the same 32-byte `H_A`, the
target-signed successful `AuthResult` echoes it, and the target freezes it in the
authenticated session. Ordinary non-federated AUTH requires all three fields to
remain empty. Missing, partial, oversized, mixed-empty, or mismatched bindings
fail closed before federation presentation or replay-state mutation. Fabric then
signs a current target session/challenge/player proof of possession that commits
the same complete signed assertion and reserves that exact presentation.
The inherited target authorization remains provisional: heartbeat, evidence,
observation refresh, and further federation export stay disabled until local
transport accepts the presentation and the exact vault grant is burned. No second
target-import screen is rendered; close, connection change, transport failure, or
pre-commit expiry sends nothing and changes no local result. Promotion also
requires the vault's non-constructible, one-shot commit receipt for the exact
target claim. The initial `Enable MCAce` decision expires at signed-policy expiry
or after 30 monotonic seconds, whichever occurs first. The target verifies both
signatures, both network keys, all bindings, audience, time, current local
session key, the immutable `H_A`, and PoP before atomically consuming bounded
replay state. Cross-network causality comes from the signed AUTH transcript, not
from comparing independent source and target wall clocks;
`source_authorized_at_epoch_ms` remains signed freshness/audit data.

The only remote claim is `FEDERATION_SOURCE_LOCALLY_VERIFIED`; it is not a
`TrustLevel`. It cannot establish/preserve local `VERIFIED`, change risk or policy
evaluation, trigger ALLOW/NOTICE/WARN/LIMIT/QUARANTINE/DENY, route, disconnect,
ban, request evidence, or repair a failed local handshake. Decline, expiry,
failure, missing state, or capacity exhaustion is availability-only and cannot
punish the player. Audit is content-free and excludes grant/presentation bytes,
keys, nonces/challenges, artifacts, evidence, screenshots, IPs, and paths.
`CONSENT_ISSUED`, `GRANT_READY`, and `OBSERVED` require a bounded confirmation
that the local append-only audit file was durably written; asynchronous queue
admission is not authorization. A queue, worker, timeout, quota, path, or disk
failure is sticky for the process: federation is disabled, its ephemeral state
is cleared, later work returns `AUDIT_FAILED`, and local authentication remains
unchanged. Both proxy commands expose content-free audit health/counters.

There is no instant remote revocation after source signing. Source pin removal
prevents new issues but cannot recall a grant already held by Fabric; expiry and
the observation-only effect ceiling bound that residual. Target replay state is
process memory: restart creates a new local session/challenge and invalidates an
old complete presentation, but a malicious client retaining an unexpired grant
and private key could create a new proof after reauthentication. This residual
window ends at signed expiry and cannot affect enforcement.

The retained federation record is
`docs/evidence/federation-durable-audit-2026-08-13.json`. The historical schema-2
matrix passed 4/4 and `-ReportOnly`; it binds older proxy artifacts/source and
does not promote the `v0.0.1` release. All four tested Velocity/Bungee
source-target combinations retained local target
`VERIFIED`/risk `0`/Paper admission, rejected same-process assertion replay,
produced content-free durable audit with healthy source/target state, and left
zero owned processes. The former P2 cold-listener readiness race is fixed by an
exact selected-port listener-ready wait after plugin initialization; its pure unit
test passed, and the retained historical restart gate passed on the first execution plus
`-ReportOnly`, recording healthy audit at both ends, `residual_reacceptance=true`, and
`durable_replay_protection=false`. Both sections keep
`fabric_gui_coverage=false`.

The normative `fabric-federation-gui-handoff-smoke.ps1` release contract is V5.
Its native evidence set is exactly seven regular files: `report.json`,
`binding.json`, `commit.json`, `visible-gui-attestation.json`, `visible-gui.png`,
append-only `runtime-events.jsonl`, and `post-run-receipt.json`. The visible
receipt and post-run receipt must be signed by two different independently
provisioned RSA keys. Their root files stay outside the repository, their SHA-256
pins must differ, and protected CI/external release policy must approve them via
`MCACE_RELEASE_APPROVED_FEDERATION_GUI_TRUST_ROOT_SHA256` and
`MCACE_RELEASE_APPROVED_FEDERATION_POSTRUN_TRUST_ROOT_SHA256`; a caller cannot
self-authorize a root by supplying a matching path and expected hash.

The GUI receipt binds a random challenge, exact attempt/session/window/process
incarnation, artifact source, Fabric target/JAR, and fully decoded PNG identity.
The ledger binds the source issue, disconnect, exact target AUTH/handoff,
promotion, live-through-expiry state, all critical process incarnations, and the
required negative attempts. After cleanup, immutable report and binding bytes are
written. A distinct external supervisor then signs a detached receipt covering
their raw hashes, the raw ledger hash/head/seal/count, GUI/PNG/pixel hashes, both
source commits, product/target/route, the V4 release-manifest hash, and exact
Fabric/Paper/source-proxy/target-proxy JAR hashes. Commit is written last and binds
the receipt hash; the receipt is not embedded in report/binding, avoiding a cycle.
Legacy source-export and target-import screens remain unreachable. Release
acceptance uses exactly one visible, connection-bound `Enable MCAce` decision on
the selected handoff run; the other two Fabric-version UI smokes add no human
approval and cannot stand in for the selected signed run.

Production validation rejects V4 documents/indexes, missing or mutated native
files, replayed GUI receipts paired with a different ledger, equal signer keys,
unapproved or repository-contained roots, and any `test_fixture=true` root or
receipt. The V5 parser and dual-PowerShell fixture suites can pass without external
private keys, but such fixture PASSes cannot close readiness. Release status is
**PENDING — Federation V5**: no production externally signed handoff evidence is
retained. Static code, self-authored receipts, report booleans, historical raw
peers, and platform-only GUI self-reports cannot establish release coverage.
