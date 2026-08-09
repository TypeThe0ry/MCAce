# Architecture

## Trust boundaries

1. The Minecraft client is attacker-controlled until a signed session is verified.
2. A client signature proves possession of a session key, not that every reported
   fact is true.
3. The Velocity or BungeeCord proxy owns admission; Paper/Folia consumes the
   resulting signed status. Routing remains a platform policy and is never a ban.
4. Behavior anti-cheat and server-authoritative state remain independent signals.
5. Cloud persistence must preserve whether evidence is server-confirmed,
   client-reported, inferred, or missing.

## Phase 1 data flow

```text
ServerHello(nonce, signed policy, required level)
          |
          v
ClientHello(public key, build, loader)
          |
          v
AuthRequest(policy digest, scoped manifests, environment hash) -- Ed25519 envelope
          |
          v
Envelope validation -> replay guard -> session transition -> risk evaluation
          |
          +--> VERIFIED/LIMITED/BLOCKED admission status
          +--> immutable SDK snapshot
```

Every signed envelope binds protocol version, packet type, session ID, timestamp,
nonce, payload length, checksum, and payload. The server rejects oversized,
expired, future-dated, corrupt, invalidly signed, or replayed messages.

## Mod-to-proxy handshake

1. The proxy creates a bounded session and sends a server-signed `SERVER_HELLO`
   containing a random challenge and an expiring, independently signed policy document.
2. Fabric verifies the envelope against a locally pinned server Ed25519 public key.
   The same pinned root verifies an embedded trust statement that authorizes a
   short-lived policy signing key. Fabric then verifies both signatures, both
   validity windows, server identity, compatibility, monotonic policy and trust
   sequences, revocation, and same-sequence digests. An unknown, revoked, or
   rolled-back policy receives no client response and no scan is started.
3. Fabric generates an ephemeral session key and sends a signed `CLIENT_HELLO`
   that binds the original challenge, public key, loader, Minecraft version, and build.
4. Fabric scans only the policy-requested built-in directory allowlist
   (`mods`, `resourcepacks`, and `shaderpacks`) plus locally consented explicit
   files (currently `options.txt`). It sends a separately signed `AUTH_REQUEST`
   binding every scope to the accepted policy digest and sequence.
5. The proxy validates size, checksum, timestamp, signature, nonce uniqueness,
   session ID, packet order, player UUID, policy compatibility, exact scope set,
   path/extension/size ceilings, and recomputed manifest roots before publishing
   a `VERIFIED` snapshot and returning a server-signed `AUTH_RESULT`.
   `AUTH_RESULT.expires_at_epoch_ms` is a signed two-minute admission-result
   freshness bound, not a heartbeat lease; a still-connected authenticated
   session continues its independently signed heartbeats after that timestamp.
6. Missing or invalid sessions become `LIMITED`. They are never automatically
   banned. The default enforcement mode records state only; an operator can opt
   into routing `LIMITED` sessions to a configured server.

7. When PostgreSQL audit storage is enabled, session transitions and risk events
   are submitted to a bounded, single-writer asynchronous queue. Database latency
   or failure is reported as an operator fault and never changes player trust,
   risk, or admission. Ordering the queue ensures the session row exists before
   related append-only events are inserted.

The client manifest remains client-reported evidence. `VERIFIED` means the pinned
challenge-response protocol completed; it does not prove that no external or
modified client code exists.

## Runtime protocol test network

`mcace-runtime-integration` is a non-production verification harness. A parent
JUnit process starts one loopback TCP server JVM and thirteen independent client
JVMs concurrently. Each socket receives its own production
`ServerHandshakeCoordinator`; clients use the production `ClientHandshakeEngine`,
signed policy verification, and policy cache. The bounded wire adapter adds only
a four-byte length prefix and rejects empty, truncated, or larger-than-2-MiB
frames before handing them to the coordinator.

The gate exercises four known-good clients plus replayed hello, forged signature,
oversized frame, truncated frame, malformed Protobuf, out-of-order auth, wrong
player UUID, unpinned root, and incompatible-build cases. Output contains only
scenario labels, direction/sequence, frame lengths, SHA-256 hashes, rejection
classes, and final snapshots; it does not dump protocol payloads or private keys.

This verifies the protocol across real process and TCP boundaries, including
concurrent connection isolation. It does not load Velocity, Fabric, Paper, or a
Minecraft server; the separate platform gate now covers that complete live
player route.

## Proxy-to-Paper/Folia admission bridge

The installed Velocity or BungeeCord adapter is the authority for network
admission. After a terminal handshake it
serializes the immutable SDK snapshot into an `ADMISSION_UPDATE`, wraps it in the
same bounded signed-envelope format, and signs it with the persistent proxy root
identity. The envelope session ID and payload UUID both bind the update to
the player connection carrying the backend plugin message.

```text
Proxy terminal snapshot
        |
        +-- root-signed mcace:admission update (15-second TTL, ordered sequence)
        v
Paper/Folia verifies pin/signature/type/timestamp/nonce/UUID/sequence/risk total
        |
        +-- publish immutable MCAceApi snapshot
        +-- expire locally if refresh stops
```

Both proxy adapters refresh active backend snapshots every five seconds and also send
after authentication, timeout, protocol violation, and server switches. Paper
accepts only a strictly increasing transport sequence that does not roll back the
snapshot evaluation time. It keeps the prior state when an invalid update is
received and removes state on player quit or transport TTL expiry.

The channel is transported over a player connection, so an attacker may be able
to submit bytes on a similarly named custom channel. Those bytes are not trusted:
Paper/Folia requires an explicitly pinned proxy Ed25519 root signature and exact
carrier-player binding. Missing or invalid pins prevent the Paper plugin from
enabling. This bridge communicates an admission decision; it does not turn a
client integrity result into an automatic ban.

The BungeeCord adapter reuses `ServerHandshakeCoordinator`, `RiskEngine`, and
`SignedAdmissionSnapshotCodec`; it does not maintain a second risk policy. Its
built-in configuration is monitor-only. Velocity retains the opt-in limited-route
adapter. Both adapters use the shared proxy transport contract: only a player may
reach authentication/payload handling; `mcace:admission` is consumed at the proxy;
and evidence, heartbeat, and bounded payload frames retain their fixed routing.
The compatibility suite verifies those boundaries, pinned signed admission output,
disconnect cleanup, and that `MONITOR` never executes a high-impact disposition.

The backend artifact declares Folia support and selects Paper or Folia scheduling
at runtime. Expiry work runs on the global scheduler; player-bound delivery and
cleanup use the owning entity scheduler; future location work has an explicit
region scheduler entry point. Real Folia process validation remains a release
gate rather than an inferred claim from unit tests.

## Proxy-safe transport budget

Every Minecraft proxy plugin-message frame is limited to 30 KiB before protobuf
parsing at the core transport entry. A small
`AUTH_REQUEST` remains backward compatible on `mcace:handshake`; a larger request
uses signed `PAYLOAD_BEGIN/CHUNK/COMMIT` envelopes on `mcace:payload`. Chunks are
limited to 16 KiB and the complete request to 1 MiB/64 chunks. Velocity and
BungeeCord use the same session-bound receiver, ordered sequence, nonce replay
guard, content hash, Merkle root, and one-minute transfer lifetime. Oversize or
invalid input degrades safely and never creates a punishment or partial manifest.

## Phase 3 Cloud control plane

Cloud clients are explicitly registered server or operator-service identities,
not Minecraft players. Authentication uses a fresh 30-second Ed25519 challenge;
a successful one-time proof yields a five-minute cloud-signed token containing
only the registry-granted scopes.

```text
registered server key
        |
        +-- sign one-time Cloud challenge
        v
scoped short-lived token
        |
        +-- risk observation ------> Cloud assigns policy weight
        +-- evidence metadata -----> global signed evidence chain
        +-- revocation request ----> review + appeal metadata
                                      |
                                      +-- signed ordered revocation
                                      +-- append-only operator audit
        +-- review/appeal --------> versioned snapshot
                                      +-- append-only transitions
        +-- player timeline ------> source-labeled observations + decisions
        +-- policy release -------> immutable weights + digest
                    |
                    +-- SHADOW -> CANARY -> BROAD -> FULL
                    +-- PAUSED / ROLLED_BACK
                    +-- baseline/candidate evaluation + reviewed metrics
```

Authentication-token keys are persisted separately from evidence/revocation
audit keys. Evidence and revocations also use distinct signature domains, so a
valid signature from one record class cannot be substituted into the other.
PostgreSQL commits each revocation and its operator audit record in one
transaction. Review and appeal snapshot changes use optimistic versions while
their transition histories and paired operator audits are append-only. The feed
communicates a signed fact and workflow results communicate human decisions;
enforcement remains an explicit consumer policy and never becomes an automatic
ban inside Cloud.

Cloud policy rollout assigns a stable 0–9999 cohort bucket from player UUID and
immutable policy ID. Every event is evaluated against the baseline and, when one
exists, the candidate. The applied version, both weights, rollout stage, and
bucket commit atomically with the risk event. Feedback joins an event to a
same-player reviewed outcome; aggregate false-positive metrics therefore retain a
review trail rather than treating raw client disagreement as ground truth.

Cloud challenge state is shared in PostgreSQL. Quota issuance is serialized by a
singleton row lock and proof exchange atomically deletes the challenge before
verification, allowing load-balanced instances without per-process replay gaps.
The default listener remains loopback-only and expects a local TLS reverse proxy.
Dashboard UI and end-user portal flows remain later Phase 3 gates.

## Policy key hierarchy

```text
Pinned server root key
        |
        +-- signs ordered trust statement (30 days)
                    |
                    +-- authorizes delegated policy key (14 days)
                                  |
                                  +-- signs operational policy (24 hours)
```

Velocity rotates the delegated key before its final two days. The replacement
trust statement has a higher sequence, contains only the new active key, and
records the former key as revoked. Clients cache both trust and policy sequences,
so an old key cannot regain authority by signing a policy with an artificially
large policy sequence. Direct root-signed policies remain supported as a recovery
path, but normal operation keeps policy signing separate from envelope identity.

## Package rules

- `mcace-protocol` has no platform dependency.
- `mcace-sdk` exposes stable immutable types only.
- `mcace-core` implements policy and state without Paper/Velocity classes.
- `mcace-storage-postgres` implements the core audit contract and owns schema migrations.
- `mcace-cloud` exposes authenticated scoped ingestion and signed revocation distribution.
- `mcace-runtime-integration` is a test harness and is not a deployable platform component.
- platform modules translate platform events into core operations.
- client scanning is explicitly rooted under caller-provided Minecraft paths.

## Third-party SDK and plugin class-loader boundary

`mcace-sdk` is a read-only snapshot contract. Its public types expose player UUID,
trust/admission state, risk band/score, policy version, evaluation time, and
bounded explainable reasons. They do **not** expose raw evidence bytes, screenshots,
encrypted-storage URIs or paths, private keys, key material, or evidence-review
handles. Administrator-only evidence commands and the local reviewer remain outside
the third-party plugin API.

The currently built Paper/Folia, Velocity, and BungeeCord adapter jars each embed
their own copy of the Java SDK classes. Paper registers `MCAceApi` with Bukkit's
service manager; Velocity and BungeeCord expose `api()` only to an embedding plugin
instance. A third-party plugin must therefore **not** assume that an independently
bundled `com.ellan.mcace.sdk.MCAceApi` has the same Java class identity as the
adapter's copy. That assumption is not portable across the three platform class
loaders and is deliberately not a supported ABI.

All three deployed plugins now expose a versioned, read-only bridge found through
each platform's normal MCAce-plugin lookup and invoked by reflection. Its v1 provider method is
named `mcaceInteropV1` and returns a
`Function<Map<String, Object>, Map<String, Object>>`; this boundary uses only JDK
bootstrap types. Player IDs are UUID values and responses use immutable primitive,
`String`, `Map`, and `List` values. A major-version mismatch, unknown map field,
malformed value, absent plugin, or failed reflective call is treated as "state
unavailable", never as verified state. The bridge has only snapshot/session and
content-free evidence-summary reads: it cannot request capture, retention,
deletion, raw evidence, keys, filesystem locations, or a punitive action.

`SdkCompatibilityContractTest` inspects the actual shadow jars, verifies the
BungeeCord service-provider metadata, proves the isolated SDK class identities,
locks the current Java snapshot surface against sensitive handles, and exercises
the JDK-only bridge through isolated SDK copies. Each platform module also locks
the public provider method to the zero-argument JDK `Function` signature.

## Evidence metadata chain

PostgreSQL serializes evidence appends by locking a singleton chain head. Each
entry binds the previous hash, global sequence, evidence/player/session IDs,
origin, timestamps, content size/hash, storage URI, and operator ID. The resulting
SHA-256 value is signed with Ed25519 and stored with its signer key ID.

Risk events and evidence metadata reject `UPDATE`, `DELETE`, and `TRUNCATE` through
database triggers. Verification recomputes every link and signature and compares
the final value to the stored head. This detects mutation; it does not make the
database or external object storage intrinsically trustworthy. Raw evidence stays
outside PostgreSQL and is referenced by a content-addressed URI and SHA-256.

Cloud periodically commits that evidence head together with complete ordered
revocation and operator-audit digests into a predecessor-linked audit anchor.
Each anchor has a domain-separated Ed25519 signature. A leased PostgreSQL outbox
uses `FOR UPDATE SKIP LOCKED` so one of many Cloud instances publishes each
pending anchor to a configured external HTTPS ledger; append-only publication
receipts bind the remote receipt reference and response-body hash. The remote
ledger must retain exact requests and deduplicate by anchor ID.

## Compatibility baseline

- Minecraft/Paper: 1.21.1
- Java: 21
- Velocity API: 3.5.1 (last stable Java 21-compatible baseline selected for this milestone)
- Fabric Loom: 1.14.10 remap plugin
- Fabric API: 0.116.15+1.21.1
