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
winning rule; when the event is late or bound to a stale session; or when the
current admission is not `VERIFIED`. Duplicate deliveries cannot repeat an action,
and bounded queue/cache limits prevent an untrusted event stream from creating an
unbounded executor state. Evidence refusal, unsupported scope, decline, expiry,
transfer failure, or missing content is not a disposition trigger. Client evidence
remains `CLIENT_REPORTED` and cannot independently justify punishment.

## Audit provenance and availability

- Every persisted observation is labeled `SERVER_CONFIRMED`, `CLIENT_REPORTED`,
  `INFERRED`, or `MISSING`; storage does not promote a client claim into a
  server-confirmed fact.
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

### Recorded process-load security gates

The final process smoke records are retained as machine-readable evidence:

- Velocity + Paper passed at
  `build/platform-smoke/runs/20260808T171235524Z/report.json` using fixed
  official Velocity 3.5.1-615 and Paper 1.21.1-133 hashes.
- BungeeCord + Paper passed at
  `build/platform-smoke-bungee/runs/20260808T173618257Z/report.json` using
  fixed BungeeCord build 2028 and Paper 1.21.1-133 hashes.
- Folia + Paper plugin passed at
  `build/platform-smoke-folia/runs/20260808T202505461Z/report.json`. Exact
  Folia 1.21.1 was unavailable; official Folia 1.21.4-6 `ALPHA` was tested and
  its Fill object URL and SHA-256 are recorded in the report.

Each gate used loopback-only listeners, an independent run root, signed/pinned
artifact checks, and cleanup with zero run-owned processes. These are process
and admission-boundary checks, not proof of every player-flow path. The Folia run
exercised global expiry plus a real offline test player's region/entity admission
consumption and PlayerQuit cleanup paths. The peer used an ephemeral test signing
key which the script deleted; it does not prove online-mode authentication or
production proxy forwarding. A separate test-only raw Minecraft peer run reached
the live Velocity/Bungee handshake and Paper admission boundary.

The Folia run exposed a deterministic shutdown compatibility issue: reflection
against Folia's non-public scheduled-task implementation could not invoke its
public `cancel()` member. The implementation now calls the public
`ScheduledTask` interface, has a regression for a hidden implementation, and
makes shutdown idempotent when the scheduler is already halted. The positive
Folia log is scanned for scheduler/thread failures; the expected missing-pin
failure is kept in a separate log and explicitly excluded from that positive
scan.

### Recorded test-only raw peer gate

The `MinecraftProxyPlayerProbeTest` uses a bounded raw Minecraft 1.21.1 wire peer,
not a standalone client product. The latest passing run IDs are
`velocity-2026-08-08T21-05-56-077744500Z` and
`bungee-2026-08-08T21-05-11-821390700Z`; both reached accepted `AUTH_RESULT`, and
Paper logs recorded `admission=VERIFIED, trust=VERIFIED, risk=0`.

Repository-relative reports:

- `build/runtime-player-probe/runs/velocity-2026-08-08T21-05-56-077744500Z/report.json`
- `build/runtime-player-probe/runs/velocity-2026-08-08T21-05-56-077744500Z/report.md`
- `build/runtime-player-probe/runs/bungee-2026-08-08T21-05-11-821390700Z/report.json`
- `build/runtime-player-probe/runs/bungee-2026-08-08T21-05-11-821390700Z/report.md`

Absolute paths:

- `C:\Users\TT\Documents\GitHub\MCAce\build\runtime-player-probe\runs\velocity-2026-08-08T21-05-56-077744500Z\report.json`
- `C:\Users\TT\Documents\GitHub\MCAce\build\runtime-player-probe\runs\velocity-2026-08-08T21-05-56-077744500Z\report.md`
- `C:\Users\TT\Documents\GitHub\MCAce\build\runtime-player-probe\runs\bungee-2026-08-08T21-05-11-821390700Z\report.json`
- `C:\Users\TT\Documents\GitHub\MCAce\build\runtime-player-probe\runs\bungee-2026-08-08T21-05-11-821390700Z\report.md`

Both reports have `remaining_run_processes=[]`. Velocity modern forwarding and
Bungee IP forwarding were enabled against Paper, but the probe remains
loopback/offline and does not cover real Fabric GUI/framebuffer capture,
Mojang/Microsoft online-mode authentication, or public-network deployment.
Fabric's ACK sequence, resize/generation cancellation, and
buffer clearing are covered by 49 common/Fabric tests; a real GUI/framebuffer
evidence-flow smoke remains unverified.

## Privacy boundary

Allowed roots are the active Minecraft instance's `mods`, `resourcepacks`,
`shaderpacks`, and explicitly selected configuration files. The built-in client
currently consents only to `options.txt`; a server policy cannot silently expand
that set. Symlinks are not followed. The scanner enforces file-count, file-size,
extension, path-containment, and policy scope ceilings.

Forbidden collection includes unrelated files, keystrokes, camera, microphone,
browser data, private documents, hidden persistence, and kernel-level inspection.
The Fabric build also has a bytecode privacy regression gate that rejects links to
AWT Robot/screen capture, JNA/User32, process enumeration, keyboard hooks, and
Windows module enumeration. This does not replace code review, but makes an
accidental desktop/process inspection dependency a test failure.

Screenshot permission is request- and scope-specific. Fabric supports only one
`GAME_RENDER_FRAME` after the player selects `Allow once` on a visible prompt.
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

## Current detection hypothesis

A valid handshake confirms that the peer possessed the ephemeral private key and
answered a fresh challenge using a client that can produce the configured protocol
and manifest. It does not confirm absence of injection, external memory tools,
automation, kernel/DMA access, or a patched scanner. Those require independent
server behavior signals. MCAce does not introduce an Agent or claim Mod-only
visibility into unrelated processes, kernel state, or external hardware.

## Cross-network federation boundary

The versioned federation protocol and attack corpus are implemented; proxy/Fabric
runtime release gates remain disabled by default. The normative threat model,
four-message state machine, privacy contract, residual risks, and release matrix
are in `docs/FEDERATION.md`.

Federation is client-carried. It has no source-target control channel, HTTP or
socket service, callback, token broker, Cloud dependency, target-initiated source
request, or live redemption. An authorized source operator explicitly issues a
target-specific consent request. Fabric shows `Allow once`, the source signs a
grant, and Fabric retains that grant plus its short-lived source-session key only
in bounded memory. Source and target identity keys are independently pinned in
the two operators' offline configurations and are bound into consent/assertion.

After receiving a complete grant, Fabric may carry it across source disconnect
or source proxy restart until its signed expiry of at most five minutes. The
target must first independently authenticate the player locally as `VERIFIED`
using the same short-lived client key. Fabric then signs a current target
session/challenge/player proof of possession. The target verifies both
signatures, both network keys, all bindings, audience, time, current local
session key and PoP before atomically consuming bounded replay state.

The only remote claim is `FEDERATION_SOURCE_LOCALLY_VERIFIED`; it is not a
`TrustLevel`. It cannot establish/preserve local `VERIFIED`, change risk or policy
evaluation, trigger ALLOW/NOTICE/WARN/LIMIT/QUARANTINE/DENY, route, disconnect,
ban, request evidence, or repair a failed local handshake. Decline, expiry,
failure, missing state, or capacity exhaustion is availability-only and cannot
punish the player. Audit is content-free and excludes grant/presentation bytes,
keys, nonces/challenges, artifacts, evidence, screenshots, IPs, and paths.

There is no instant remote revocation after source signing. Source pin removal
prevents new issues but cannot recall a grant already held by Fabric; expiry and
the observation-only effect ceiling bound that residual. Target replay state is
process memory: restart creates a new local session/challenge and invalidates an
old complete presentation, but a malicious client retaining an unexpired grant
and private key could create a new proof after reauthentication. This residual
window ends at signed expiry and cannot affect enforcement.
