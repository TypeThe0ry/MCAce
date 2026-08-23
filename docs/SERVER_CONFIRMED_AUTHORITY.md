# Server-confirmed backend authority contract

Status: Phase 1 protocol/verifier, Phase 2.5 hardened durable issuance, and the
Phase 2.6 inert Paper coordinator are implemented and default-disabled. A real
GrimAC 2.3.74 loopback run now proves the observational behavior-correlation
path can emit `SERVER_CONFIRMED` CloudRiskEvents; the signed Phase 1 authority
channel, production topology, and release coverage remain open.

This document defines the minimum security boundary for a future production
`SERVER_CONFIRMED` behavior observation that may enter MCAce's high-impact
disposition path. The repository contains the inert protocol/verifier foundation
and a durable-before-return issuance primitive. The current Grim adapter is a
separate CloudRiskEvent producer for observational correlation only: it is
bound to a real Paper/Leaf loopback process in
[`anti-cheat-real-server-2026-08-23.json`](evidence/anti-cheat-real-server-2026-08-23.json),
but it is not the signed backend-authority producer described by this contract.
Vulcan, Fabric evidence, backend context, Cloud production topology, and any
punitive release behavior remain separate gates.

The current repository has a hardened `ADMIN_REVIEWED` authorization and
execution *downstream*:

- `TrustedDispositionAuthorizationRuntime.authorizeAdministratorReview()`
  evaluates the operator-reviewed observation against the current signed policy;
- the V3 journal is forced to durable storage before an executable event is
  returned;
- Velocity and Bungee revalidate the exact policy, winning rule, action, physical
  login, authenticated session, verified admission, backend readiness, and
  execution context at action time;
- `CLIENT_REPORTED` and inferred observations cannot independently select
  `LIMIT`, `QUARANTINE`, or `DENY`;
- `DENY` ends only the current physical connection and never creates a permanent
  ban.

The signed `SERVER_CONFIRMED` authorization entry point and production source
feeding that downstream are still intentionally absent. The observed Grim
`SERVER_CONFIRMED` value is an origin on the observational CloudRiskEvent and
does not by itself authorize a disposition. Adding a signed producer and
production wiring is a separate release gate.

## Current Phase 1 through Phase 2.6 implementation boundary

The safe, default-disabled protocol foundation is implemented:

- packet types 21 and 22, bounded protobuf messages for
  `BackendAuthorityGrant` and `ServerAuthorityObservation`, and a reserved
  `mcace:authority` channel constant;
- strict grant and observation codecs that apply bounded signed envelopes,
  replay checks, byte-for-byte canonical outer-envelope and payload encoding,
  unknown-field rejection, short expiry, and exact lifecycle bindings;
- an immutable registry that pins the carrying registered backend to one exact
  backend instance, canonical Ed25519 public key/fingerprint, and canonical
  authority profiles. Each profile digest is checked against its exact provider
  contracts, quorum, shared maximum window, and cooldown; an empty registry is
  the disabled state;
- a narrow `VerifiedServerAuthorityObservation` that callers outside the
  authority package cannot construct, with no origin, confidence, policy,
  action, rule, route, kick, or ban selector. It retains the SHA-256 of the exact
  signed frame that passed verification.
- the package-private abstract issuance-journal contract, which requires every
  implementation to define `lastSequence` and provides no default-zero recovery;
  the package-private file implementation opens only an operator-preprovisioned
  regular file with the exact versioned header. Runtime has no create or initialize
  path. A public read-only preflight returns the exact required header bytes and
  validates provisioning without creating or changing the directory, file,
  header, or records. The file implementation holds one handle and an exclusive
  lock for its full lifetime, rejects unsafe identity, corrupt, partial,
  over-quota, duplicate, and non-increasing records, and poisons that instance
  after any I/O, identity, or post-force verification failure;
- `DurableServerAuthorityIssuer`, the only public production issuance primitive.
  The raw codec signer and its undurable result are package-private, and the
  issuer's `recover(VerifiedGrant)` returns a non-externally-constructible
  `RecoveredServerAuthoritySequence`, so callers cannot supply an untyped restart
  value. Issuance allocates `last + 1` and creates a non-externally-constructible
  sendable token only after the matching record has been appended, forced, and
  re-read. The token binds the exact grant, lifecycle, backend key, and
  observation/issuance/expiry window. Any journal I/O, identity, force, or
  post-force verification failure latches the issuer poisoned until close/reopen;
  pre-journal semantic rejection, including a grant/key mismatch, does not poison
  it;
- a `PaperServerAuthorityLifecycle` seam instantiated in the disabled state by
  `MCAcePaperPlugin`. Its enabled test seam prepares at most one issuance and
  returns a unique lease capability. Commit requires both that lease and the
  matching durable token; abort releases the pending issuance so a fresh prepare
  can retry. Restart recovery accepts only the typed sequence returned from the
  issuer for the verified grant. It retains no grant while disabled, has no
  configuration, provider, or sender dependency, and is not connected to a plugin
  channel, trusted authorization, or executor.
- the package-private `PaperServerAuthorityIssueCoordinator`, which is not
  instantiated by `MCAcePaperPlugin`. It applies an exact request/lease/grant
  precheck, requires the journal-backed issuer to allocate and force the exact next
  sequence, and commits the matching durable token before returning an opaque
  capability. Its durable result exposes no raw frame to Paper because the frame
  accessor remains package-private to the core authority package. Typed sequence
  drift removes the lifecycle and requires fresh `recover(VerifiedGrant)` state;
  uncertain I/O, runtime uncertainty, abort failure, or a post-durability commit
  failure poisons the coordinator and never retries the advanced sequence.

The JDK 21 offline authority selections passed 8 suites and 51 tests with zero
failures/errors and one host-capability symlink skip. These are library tests. The
current root build covers Phase 2.6 at 147 suites and 681 tests with zero failures
or errors; isolated modern Fabric adds 24 suites and 74 tests, for 171 suites and
755 tests combined. The current real-server evidence is separate from these
library tests and is recorded in the anti-cheat evidence file linked above.

This foundation has no Phase 1 production authority runtime path. In
particular, no Velocity, BungeeCord, Paper, or Folia plugin registers the
reserved authority channel or sends an authority frame, and the signed
grant/observation lifecycle is not wired to trusted authorization/execution.
The separate Paper behavior pipeline does have a real Grim loopback producer,
but it emits only observational CloudRiskEvents and the release contract keeps
`MONITOR`/`NONE`; it must not be described as a live signed authority producer
or as production punitive coverage.

## Non-negotiable boundary

The first acceptable producer is a Paper/Folia-local behavior authority, carried
to the current proxy over an independently signed backend channel:

```text
real server behavior providers
  -> same-session, same-backend independent correlation
  -> durable Paper issuance record
  -> Paper Ed25519 attestation
  -> proxy backend-key/session/lifecycle verification
  -> durable trusted authorization
  -> existing atomic Velocity/Bungee action gate
```

This stays within the current product boundary. It requires no Cloud service,
Agent, standalone client, additional Mod loader, or new process.

The attestation reports an observation, never a punishment. It must not contain a
disposition action, rule ID, route target, kick command, or an origin/confidence
chosen by Paper. Only the proxy verifier may construct the narrow internal
`SERVER_CONFIRMED` + `CONFIRMED` observation, and only the current root-signed
policy may choose an action.

## Sources that must not be promoted

The following signals remain useful in their present audit or admission roles,
but none may be converted into this authority type.

### Fabric observations

`AuthenticatedManifestObservationDeriver` deliberately labels manifest and
dynamic observations `CLIENT_REPORTED` with low confidence. A session signature
proves who submitted bytes; it does not prove the client's filesystem claim.
Having Paper re-sign the same client statement does not make it server-confirmed.

Relevant boundary:

- `mcace-core/.../proxy/AuthenticatedManifestObservationDeriver.java`
- `mcace-core/.../session/ServerHandshakeCoordinator.java`
- `mcace-server-velocity/.../MCAceVelocityPlugin.java`

### Shadow backend context

`BackendContextCodec` is intentionally unsigned, while
`ShadowBackendContextRuntime` and `ShadowBackendContextAuditRecord` explicitly
have no disposition hook. World and game-mode context may constrain or explain an
already-authorized action; it is not cheating evidence.

Relevant boundary:

- `mcace-core/.../context/BackendContextCodec.java`
- `mcace-core/.../proxy/ShadowBackendContextRuntime.java`
- `mcace-core/.../proxy/ShadowBackendContextAuditRecord.java`

### Existing behavior correlation and Cloud records

`BehaviorAlertCorrelator` is not bound to the proxy authenticated session,
physical login, backend generation, or admission sequence. Its persistence-domain
origin enum and `CloudRiskEvent` are not the disposition-domain authority type.
The current pipeline is optional Cloud delivery and must remain disconnected from
high-impact execution.

The current typed Grim adapter is already an input to the existing local
behavior correlator and Cloud event; the real loopback evidence records that
path. Raw Grim or licensed Vulcan events must not be reused as the verified
signed authority output. A future local authority correlator must bind the
same-session/backend grant, durable issuance, independent provider profile,
and signed observation before any trusted disposition can consume it.

Relevant boundary:

- `mcace-server-paper/.../behavior/BehaviorAlertCorrelator.java`
- `mcace-server-paper/.../behavior/BehaviorAlertPipeline.java`
- `mcace-cloud-client/.../CloudRiskEvent.java`

### Protocol risk and action feedback

Handshake risk audit records are admission evidence, not behavior authority.
Likewise, a backend observing an action already ordered by the proxy cannot feed
that observation back as new authority; doing so would create a self-confirming
loop.

## Protocol

Phase 1 reserves a dedicated bidirectional `mcace:authority` channel and defines
the messages below, but no platform registers that channel. A future production
integration must not reuse `mcace:context` or change the meaning of signed
admission snapshots.

### Proxy to Paper: `BackendAuthorityGrant`

The proxy signs a short-lived grant containing at least:

- schema and packet version;
- unique grant ID and random challenge/commitment;
- proxy instance ID and exact backend instance ID;
- player UUID and exact proxy authenticated session ID;
- an opaque binding ID regenerated for each physical login and backend
  generation;
- admission transport sequence and monotonic grant sequence;
- issued-at and expires-at timestamps.

The TTL should initially match the current short admission window. A backend
transition invalidates the previous grant before the transition begins; a new
grant is issued only after the new backend is ready. Paper verifies the grant with
the pinned proxy public key and binds it to the carrying Bukkit player. A client
can never originate this packet.

### Paper to proxy: `ServerAuthorityObservation`

Each Paper instance uses its own Ed25519 key. Proxy configuration maps the exact
registered backend to a backend instance ID, one canonical key/fingerprint, and
digest-keyed full canonical authority profiles; it does not accept an unbound
allowlist of digest strings.

The signed payload contains at least:

- schema, packet type, attestation ID, backend instance ID, and key ID;
- player UUID, exact proxy session ID, grant ID/commitment, physical-login
  binding ID, and admission sequence;
- strictly increasing observation sequence for that binding;
- observed-at, issued-at, and expires-at timestamps;
- canonical authority-profile SHA-256;
- the set/commitment of independent provider trust domains;
- content-free provider versions, stable check families, thresholds, and window
  results.

The payload contains no raw coordinates, IP address, verbose alert text, client
file path/hash, disposition action, policy rule, route, or ban instruction.

Reuse the bounded Ed25519 envelope and replay primitives in:

- `mcace-protocol/.../crypto/EnvelopeCodec.java`
- `mcace-protocol/.../crypto/NonceReplayGuard.java`

Do not treat `SignedAdmissionSnapshotCodec` as a complete reverse authority
protocol; its present envelope binding is narrower than the session and physical
login binding required here.

## Provider independence and authority profiles

Automatic `LIMIT` or stronger action requires at least two operator-approved,
independent trust domains by default. Both must:

- observe the same player, authenticated session, physical binding, and backend;
- independently meet their configured threshold in the same bounded window;
- use eligible stable checks from an operator-pinned version contract;
- exclude cancelled, experimental, or unclassified checks;
- be normalized through a fixed provider registry, not arbitrary frame strings.

Aliases or two adapters backed by the same underlying signal do not create two
independent providers.

The canonical authority-profile digest commits, with provider contracts ordered
by provider ID, to every exact provider ID, independent trust-domain ID, provider
version, stable check family, and threshold, plus the independent-domain quorum,
shared maximum provider window, and cooldown. The registry rejects a digest that
does not match that canonical profile content. During verification, every signed
provider summary must exactly match its pinned contract and meet its threshold;
all accepted provider windows must lie within the one profile-bounded window
ending at `observed_at`, begin no earlier than the live grant, and satisfy the
pinned independent-domain quorum. Any profile change produces a different
digest. A future policy selector must use the exact digest, never a broad string
such as `grim`, `vulcan`, or a check name.

If only one approved provider exists, its output remains audit/WARN or enters the
existing `ADMIN_REVIEWED` workflow. It is not single-source automatic
`SERVER_CONFIRMED` enforcement.

## Proxy validation order

Future receiving Velocity or Bungee code must fail closed in this order:

1. enforce packet size, field-count, list-count, and unknown-field limits;
2. require the carrying source to be the player's exact current backend;
3. consume and reject client-originated packets without parsing them as authority;
4. under the player's lifecycle lock, require the exact player object/login
   ticket, authenticated session, `VERIFIED` admission, backend-ready state, and
   current backend; load the live `BackendAuthorityGrantCodec.VerifiedGrant` and
   the optional `PriorAcceptedObservation` for that physical binding;
5. derive the backend identity from the proxy connection, select its exact pin,
   and invoke observation verification without releasing that lifecycle lock;
6. reject any outer `SignedEnvelope` or decoded observation payload whose bytes
   differ from canonical protobuf reserialization, as well as unknown outer,
   payload, or nested-provider fields; then verify packet/session binding,
   Ed25519 signature, key ID, timestamp, nonce, and checksum;
7. require the supplied live `VerifiedGrant` to match the current player,
   authenticated session, physical binding, admission sequence, and pinned
   backend instance and to remain unexpired; require the observation's exact
   grant ID/commitment and time range to be bounded by that grant;
8. resolve the signed profile digest to the exact canonical pinned profile, match
   every provider ID/domain/version/family/threshold, enforce its quorum and
   shared window, and enforce the prior snapshot's strictly increasing sequence
   plus cooldown over both observed-at and issued-at;
9. create the narrow `VerifiedServerAuthorityObservation`, including the SHA-256
   of the exact accepted signed frame, and commit its new prior snapshot/sequence
   before releasing the same lifecycle lock;
10. outside the lifecycle lock, durably authorize it through a future trusted policy
   runtime;
11. queue only the event returned after a successful journal force;
12. let the existing executor atomically revalidate lifecycle, context, policy,
    rule, action, and expiry while initiating the action.

If the player reconnects between steps 9 and 12, the durable journal may record an
authorization that was never executed; the existing exact-session/physical-login
gate must reject the stale event.

This sequence remains the production target. Phase 1 implements the bounded,
canonical frame and payload checks, cryptographic checks, exact registry/profile
checks, live-grant comparisons, prior-snapshot sequence/cooldown checks, and
narrow token. It cannot itself prove packet provenance or acquire a platform
lifecycle lock: a future caller must supply the real current facts and hold the
same lock across reading the prior snapshot, calling `verify`, and committing the
returned sequence/times. No current caller registers a receiver, persists that
snapshot or an authorization, or calls an action executor. Phase 2.5 adds hardened
durable local issuance and a disabled Paper lifecycle seam; Phase 2.6 adds only the
package-private inert coordinator that atomically orders exact precheck, durable
next-sequence issuance, and exact commit. Neither satisfies platform provenance,
receiver, sender, correlation, authorization, or execution requirements.

Production wiring should accept only `VerifiedServerAuthorityObservation`.
Raw `ArtifactObservation` construction of a `SERVER_CONFIRMED` source should be
restricted to a package-private test seam so a future caller cannot gain authority
by setting enum values.

## Durable records

### Paper issuance journal

The implemented journal/issuer contract appends and forces an issuance record
before returning a token from which an adapter could send the attestation. It
records only:

- attestation ID and backend-key fingerprint;
- observation sequence;
- session/binding commitment;
- provider-set/profile commitment;
- observed/issued/expires timestamps;
- exact emitted signed-frame SHA-256.

The operator must create the journal directory and regular journal file, write
the exact fixed versioned header, and apply the intended ownership and ACLs
before MCAce starts. Runtime exposes no create or initialize operation and fails
closed if either path is missing or unsafe. Its public provisioning preflight is
read-only: it supplies the exact required header bytes and validates a supplied
path without creating or modifying the directory, file, header, or records. This
removes an ambiguous empty-file bootstrap from the authority path and makes
provisioning a separate, reviewable operation.

The initial file is exactly the following ASCII/UTF-8 line followed by one LF
byte, with no BOM, CR, blank prefix, or extra record:

```text
MCACE_SERVER_AUTHORITY_ISSUANCE_JOURNAL_V1
```

One journal instance keeps a single read/write file handle and an exclusive file
lock until close. On Windows with the supported OpenJDK 21 runtime it additionally
opens that handle with `NOSHARE_DELETE` and `NOSHARE_WRITE`; startup fails closed
if those OpenJDK options cannot be applied. On non-Windows hosts it requires a
non-null filesystem `fileKey`. Both paths reject symbolic links and special files
and recheck the no-follow identities of the journal and all existing ancestors.

For each issuance, the journal reads and decodes through that same long-lived
handle, validates the next record, appends it, calls `force(true)`, and decodes
the complete bytes again through the same handle. It then performs the required
no-follow path/identity and canonical-path-resolution checks. Any I/O, identity,
force, or post-force verification failure returns no token and poisons the
journal and issuer instances until they are closed and reopened. Semantic
rejection before journal I/O, including a grant/key mismatch, also returns no
token but does not poison the issuer.

The issuer treats the journal as the sequence authority. Its
`recover(VerifiedGrant)` operation reads the last committed sequence for that exact
grant/lifecycle and returns it only as non-externally-constructible
`RecoveredServerAuthoritySequence`. Issuance signs `last + 1` and appends that
record before returning a durable token that binds the exact verified grant,
lifecycle, backend key, and observed/issued/expires window. There is no separate
in-memory allocation that can advance before append. If a journal I/O outcome is
uncertain, the poisoned issuer cannot retry; a later clean reopen derives the next
value from what is actually durable.

The Paper lifecycle seam mirrors that ordering with capability-bound
prepare/commit/abort. Prepare reserves at most one pending issuance and returns a
unique lease; commit accepts only the matching lease and matching durable token.
Abort releases a pre-durability rejection so a new prepare can retry. The Phase
2.6 coordinator performs an exact request/lease/grant precheck, delegates sequence
allocation to the journal-backed issuer, and commits before returning its opaque
durable capability. Raw frame access remains package-private to core. A sequence
drift exception removes lifecycle state and requires a fresh typed recovery; an
uncertain I/O outcome or a commit failure after durability poisons the coordinator
and must never take the abort/retry path. A future
production startup must call issuer recovery for the verified grant and install
that typed recovered sequence before accepting it. This seam remains disabled in
`MCAcePaperPlugin`; the plugin does not instantiate the coordinator, and no current
production adapter can obtain or send the raw frame.

These checks establish a fail-closed runtime append contract, not storage
immutability against a local administrator. Pure JDK code cannot prove correct
NTFS/POSIX ACLs, defeat a privileged administrator or hostile storage stack, or
detect bytes changed after a token has already been returned and the runtime
boundary has ended. Operators must isolate the directory to the MCAce service
identity, monitor ownership/ACL changes, and use independently protected audit or
immutable storage where post-return tamper evidence is required. The Windows
no-share options are OpenJDK-specific rather than a Java SE portability guarantee;
the non-Windows `fileKey` check likewise depends on a filesystem that exposes a
stable key.

### Proxy authorization journal

Keep the existing durable-before-event rule. Prefer a new V4 record for this
origin so it additionally binds source attestation ID, the verified token's exact
`signedFrameSha256`, backend key fingerprint, authority-profile digest, and
source expiry. V3 remains the stable `ADMIN_REVIEWED` contract.

The executable event must carry the authority expiry separately from the policy
expiry. The action gate uses the earlier deadline and must not overload the
current policy-expiry field.

## Platform integration points

### Paper and Folia

- initialize the grant receiver, provider registry/correlator, signer, and
  operator-preprovisioned issuance journal beside admission messaging in
  `MCAcePaperPlugin`;
- keep authority disabled if any key, registry, journal, or provider contract is
  invalid;
- recover the exact lifecycle's typed `RecoveredServerAuthoritySequence` from
  `recover(VerifiedGrant)` before accepting that grant, then instantiate the inert
  coordinator only inside the completed production adapter. Use its exact
  precheck/durable-next-sequence/commit ordering; retry only pre-durability
  rejection, never uncertain I/O or a post-durability commit failure;
- run player-owned work through `MCAceRuntimeScheduler` and clear all binding
  state on quit/replacement;
- keep `PaperBackendContextPublisher` shadow-only;
- allow local authority operation when Cloud is disabled.

### Velocity

- load the exact backend-key/profile registry with the trusted policy runtime;
- register the dedicated channel and create grants when forwarding a current
  signed admission snapshot;
- invalidate grants on replacement, disconnect, or backend-connecting, then issue
  a new grant only after backend-ready;
- verify the observation using the same lifecycle facts later rechecked by
  `VelocityDispositionExecutor`.

### BungeeCord

- apply the equivalent backend-key registry, channel, grant lifecycle, and
  verifier;
- bind to `BungeeDeferredDispositionRoutes` login tickets, not only session text;
- invalidate at `ServerConnectEvent` before a backend transition and restore
  readiness only for the exact completed connection;
- optional/third-party session bridges without the exact lifecycle facts remain
  fail closed.

## Required test gates

### Protocol and core

Cover valid frames and every wrong key/backend/carrier/player/session/grant/
binding/admission-sequence combination; missing/stale `VerifiedGrant`;
duplicate/decreasing sequence; cooldown violations; replayed nonce;
expired/future/oversized/unknown-field and noncanonical outer/payload frames;
reconnect/backend-switch/Paper-restart/proxy-restart replay; provider contract
drift, aliasing, shared-window violations, and cross-session quorum; canonical
profile-digest drift; exact signed-frame SHA binding; journal
I/O/quota/symlink failure; policy rollback, equivocation, expiry, and action
mismatch; queue/idempotency capacity.

### Platform adapters

For both proxies prove client-source consume-only, stale backend rejection,
transition invalidation, lifecycle capture before durable authorization, and exact
execution-time recheck. Prove `MONITOR` creates only audit evidence, deferred
events expire safely, and `DENY` affects only the current physical login.

For Paper/Folia prove no signer without complete configuration, no provider input
before a valid grant, correlation cleanup on every lifecycle transition, Folia
player-owned scheduling, Cloud independence, and no direct route/disconnect call
from a raw provider event.

### Real processes

Test fixtures may validate the protocol but must be labelled
`TEST_ATTESTATION_FIXTURE`; they are not release evidence for a genuine producer.
The release gate uses the selected real providers across:

- Velocity + Paper: LIMIT, QUARANTINE, DENY/reconnect;
- Bungee + Paper: LIMIT, QUARANTINE, DENY/reconnect;
- at least one Velocity/Folia and one Bungee/Folia lifecycle case.

Each case proves two real independent sources, Paper durability before send,
exact backend key/profile, proxy durability before execution, common attestation
and authorization identity, exact physical/session/context binding, route result,
current-connection-only DENY, clean independent reconnect, no ban/cross-session
state, and zero owned process residue.

## Rollout and operator decisions

Production producer integration cannot begin until the operator freezes:

1. provider trust domains (for example typed Grim, an operator-supplied licensed
   Vulcan, or a future native deterministic detector);
2. eligible versions/check families, exclusions, thresholds, window, cooldown,
   quorum, and independence mapping;
3. one Ed25519 key per Paper instance, key IDs, proxy pins, rotation overlap,
   revocation, permissions, and backup policy;
4. proxy/backend instance topology and key mapping during scaling/replacement;
5. the rollout action ceiling.

The required rollout is:

1. protocol, key registry, narrow verified type, and negative tests
   (implemented as a default-disabled library, with no platform wiring);
2. hardened Phase 2.5 durable issuer/journal and disabled Paper capability-bound
   lifecycle seam, plus the Phase 2.6 package-private inert coordinator (library
   slices implemented); production instantiation, grant receiver, authority
   configuration, provider correlation, configured signer, sender, trusted
   authorization/executor wiring, and process evidence remain open;
3. Velocity/Bungee verification in `MONITOR` with no action wiring;
4. real provider process evidence on Paper/Folia and both proxies;
5. two-source `LIMIT` only;
6. separately approved `QUARANTINE` after false-positive/fault-injection evidence;
7. separately approved current-connection-only `DENY` last.

Automatic permanent banning remains prohibited at every phase.

Until the provider, profile, key, topology, and rollout choices are fixed, the
correct repository state is the present inert protocol, durable-issuance libraries,
disabled Paper lifecycle seam, package-private uninstantiated coordinator, and a
pending production release gate—not a synthetic producer.
