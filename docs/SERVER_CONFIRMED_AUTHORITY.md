# Server-confirmed backend authority

## Current release boundary

The signed Paper/Folia to proxy authority path is now implemented and wired on
all three server platforms, but it is deliberately **opt-in and MONITOR-only**.
The current code can:

1. issue a short-lived, proxy-signed `BackendAuthorityGrant` for an exact
   authenticated physical login and ready backend;
2. receive and verify that grant on Paper/Folia;
3. correlate exact-profile alerts from independent Paper anti-cheat providers;
4. append and force a durable Paper issuance record before exposing a sendable
   signed `ServerAuthorityObservation`;
5. send the observation back over `mcace:authority`; and
6. verify it on Velocity or BungeeCord while holding the platform lifecycle
   lock, then record a content-free MONITOR log entry.

It does **not** feed the verified observation into
`TrustedDispositionAuthorizationRuntime`, a disposition queue, or a platform
action executor. A verified authority frame therefore cannot currently select
or execute `LIMIT`, `QUARANTINE`, `DENY`, kick, or ban. Automatic permanent
banning remains outside the product contract.

The implementation has unit and integration-fixture coverage. It does not yet
have release-grade real-process evidence for a complete Paper/Folia plus
Velocity/Bungee topology, a licensed genuine Vulcan event, restart/replay
acceptance, or a production action-ceiling freeze. Until those gates are
captured from an exact immutable commit, this path must not be presented as
production enforcement or as equivalent to a kernel anti-cheat.

| Surface | Current state |
| --- | --- |
| Default configuration | `authority.enabled=false` |
| Allowed mode | exactly `MONITOR` |
| Paper/Folia receiver/correlator/signer/sender | implemented and conditionally registered |
| Velocity grant/receiver | implemented and conditionally registered |
| BungeeCord grant/receiver | implemented and conditionally registered |
| Paper durability before frame exposure | implemented |
| Proxy verification and prior-observation replay state | implemented in memory |
| Authority to disposition authorization | deliberately disconnected |
| Automatic kick/deny/quarantine/ban from authority | absent |
| Genuine production process evidence | pending |

## Trust and data flow

```text
verified client admission + exact physical login + backend-ready state
  -> Velocity/Bungee short-lived Ed25519 BackendAuthorityGrant
  -> Paper/Folia verifies grant against the pinned proxy key
  -> exact-profile independent provider correlation
  -> Paper issuance journal append + force + re-read
  -> Paper Ed25519 ServerAuthorityObservation
  -> Velocity/Bungee exact carrier/session/backend/grant/profile verification
  -> MONITOR log only
```

The signed observation is evidence, not a punishment command. Its payload has
no action, route, rule ID, kick command, ban flag, client path, IP address, raw
coordinates, or verbose provider alert. Only the proxy verifier constructs the
narrow `VerifiedServerAuthorityObservation`; its constructor is not public and
the type carries the SHA-256 of the exact signed frame that passed validation.

Client mod/resource-pack telemetry remains `CLIENT_REPORTED`. Paper re-signing
a client claim does not turn it into server-confirmed evidence. The authority
path consumes Paper-local provider callbacks and must not be confused with the
separate Cloud behavior pipeline or the unsigned shadow backend-context path.

## Activation and configuration

### Safe defaults

Paper ships the following inert root in
`mcace-server-paper/src/main/resources/config.yml`:

```yaml
behavior:
  enabled: false
authority:
  enabled: false
  mode: MONITOR
```

Velocity and BungeeCord use `authority.properties` in their MCAce data
directory. If the file is absent, `ProxyServerAuthorityConfiguration` creates
only this safe default:

```properties
authority.enabled=false
authority.mode=MONITOR
```

No authority runtime or `mcace:authority` channel is registered while disabled.
If `authority.enabled=true`, every required key, backend pin, profile, TTL, and
journal field must validate. Any other `authority.mode`, including an
enforcement-looking value, fails closed and leaves the authority runtime
disabled.

Use [`PRODUCTION_AUTHORITY_PROVISIONING.md`](PRODUCTION_AUTHORITY_PROVISIONING.md)
and `scripts/provision-production-authority.ps1` to create an offline staged
bundle. The provisioner fixes `-ActionCeiling MONITOR`, generates distinct
Ed25519 backend-observation and selected-proxy grant-signing identities,
initializes the journal header, emits the selected proxy public-key pin for
Paper, and records only sanitized public trust-root/topology/profile data in its
V3 freeze manifest. The independent evidence supervisor is not generated here:
the provisioner consumes only its external Ed25519 public descriptor and an
out-of-band approved SHA-256 pin, and records `private_key_present=false`.
The backend and proxy fingerprints must differ. The Paper snippet explicitly
freezes `behavior.enabled=true` plus the Grim and Vulcan adapter switches, while
the repository default remains false.
Generated `behavior.enabled=true` / `authority.enabled=true` snippets are activation material;
generating a bundle does not install or enable it.

### Exact profile contract

`BackendAuthorityProfile` commits these values into a canonical SHA-256:

- provider ID, independent trust-domain ID, exact provider version, stable
  check-family ID, and threshold for each provider;
- independent-domain quorum;
- maximum provider window; and
- cooldown.

Profiles contain 2-8 provider contracts and require at least two independent
trust domains. Provider ID/version fields are bounded to 32 characters and the
stable check-family field to 96 characters so the frozen profile cannot exceed
the Paper adapter event contract. A threshold is bounded to `1..256`. Paper recalculates the
profile digest from `config.yml`; the proxy independently recalculates it from
`authority.properties`. A stale digest, duplicate provider, shared-domain
quorum, unknown field, out-of-contract duration, or pin mismatch disables the
runtime rather than weakening the profile.

## Paper/Folia runtime

`MCAcePaperPlugin.enableServerAuthority()` now constructs the complete runtime
when configuration validation succeeds. `PaperServerAuthorityChannelLease`
registers the incoming and outgoing `mcace:authority` channels as one resource
acquisition. Each compensating unregister is armed before entering its matching
platform registration call, because a platform may mutate registry state and
then throw. If either registration fails, it unregisters every attempted
channels and closes the runtime/journal in reverse order. The runtime is
published to the plugin only after both registrations succeed. Disable closes
the channel lease and journal idempotently.

### Grant intake

`PaperServerAuthorityRuntime` accepts a grant only when all of the following
remain current:

- the carrying Bukkit `Player` is the exact player object associated with the
  verified admission;
- the admission is `VERIFIED` and unexpired;
- the grant is signed by the pinned proxy key;
- proxy instance, backend instance, player UUID, authenticated session,
  physical-login binding, admission transport sequence, grant sequence, nonce,
  and expiry all validate; and
- the client has registered `mcace:authority` for the server-to-proxy response.

A malformed, tampered, or replayed untrusted candidate is logged and leaves the
last valid grant intact. This prevents a bad packet from revoking a valid
MONITOR session. A newly verified grant is installed only after durable journal
recovery succeeds. Recovery failure removes the player's authority lifecycle
and provider state. Recovery is serialized through the same bounded authority
writer as issuance, so a Paper/Folia player scheduler never waits behind a
concurrent journal `force(true)`.

Routine signed-admission refresh does not rotate an unexpired authority grant
for the same backend/session/physical binding. The proxy retains the original
grant and Paper permits the newer verified admission sequence to extend the
current physical session without discarding provider events. A new grant is
created only after bounded expiry (or lifecycle/backend/session replacement),
at which point events predating the new signed grant boundary remain ineligible.

### Provider correlation

`BehaviorAlertPipeline` forwards typed Grim/Vulcan callbacks to the local
authority sink independently of optional Cloud delivery.
`PaperAuthorityProviderCorrelator` then requires exact matches for provider ID,
provider version, and stable check family; rejects experimental, future, stale,
already-consumed, and unknown-provider events; and keeps at most 256 event
timestamps per provider.

Correlation selects at most one provider per independent trust domain, in
canonical provider-ID order, and emits only after the configured threshold and
independent-domain quorum are met inside the shared profile window. Provider
callbacks may arrive out of chronological order: window start/end are computed
as the minimum and maximum timestamps rather than deque insertion order.

Cooldown is checked against both:

- the last accepted provider `observedAt`; and
- the last durably issued signed-frame `issuedAt`.

The exact boundary is accepted; a time strictly before the boundary is
rejected. Evidence is single-use: after a durable observation is committed and
its one transport send is attempted, all events at or before the consumed
timestamp are removed.

### Durable issuance before send

`DurableServerAuthorityIssuer` is the only production signing entry point. For
an exact verified grant it:

1. recovers the last durable lifecycle sequence and timestamps;
2. requires the request to match the backend key, grant, session, physical
   binding, admission sequence, provider window, and expected next sequence;
3. signs the canonical observation;
4. appends the content-free record to the issuance journal;
5. calls `force(true)` and re-reads the exact appended record through the same
   handle;
6. only then creates `DurablyIssuedServerAuthorityObservation`, whose frame can
   be passed to the platform sender.

`PaperServerAuthorityIssueCoordinator` couples that durable token to one unique
prepare/commit lease. Pre-durability semantic rejection may abort and retry. An
uncertain I/O result, sequence drift, runtime uncertainty, or post-durability
commit failure poisons/removes the affected state and must not reuse the
advanced sequence.

After commit, Paper updates its in-memory grant sequence and correlator
consumed/accepted/issued times, and makes one call to
`Player.sendPluginMessage` with the exact durable frame. There is no transport
ACK and MCAce does not retry the durable sequence, so the log says **send
attempted**, not published or delivered. This is an at-most-once transport
attempt after durability; it is still MONITOR output and has no local route,
disconnect, kick, or ban call.

Paper/Folia player schedulers enqueue immutable grant-recovery and issuance
requests into one dedicated journal writer with a bounded 256-entry queue.
Queue saturation is an immediate MONITOR rejection rather than a blocking wait
or an unbounded allocation. Journal recovery, signing, append, `force(true)`,
and exact-tail verification execute only on
`mcace-authority-journal-writer`; completion is returned through
`executeForPlayer` before the current Player/admission/grant capability is
revalidated and one send is attempted. A newer recovered grant cancels an older
durable frame whose player callback has not yet run; the recovered journal
sequence remains authoritative and the retired frame is not retried. Shutdown
stops admission, drains the writer with a bounded wait, and closes the lifetime
journal handle afterward. Unit tests prove single-thread execution, bounded
rejection, and adverse grant-recovery/send callback ordering. Production
storage-latency measurement remains a live-server acceptance item and is not
inferred from those code-level tests.

## Velocity and BungeeCord runtime

Both proxies load the same strict `ProxyServerAuthorityConfiguration`, bind
each registered backend name to one backend instance ID, Ed25519 public key/key
ID, and one or more complete canonical profiles, then register
`mcace:authority` only if that configuration is enabled.

The grant is issued only while the proxy's platform lifecycle lock proves:

- the exact physical-login ticket is current;
- the authenticated session is current;
- admission is verified;
- the exact backend connection is current; and
- the backend-ready barrier is satisfied.

Velocity checks whether `ServerConnection.sendPluginMessage` accepted the send
attempt and invalidates the grant when that call reports unavailable. It is not
a remote delivery ACK. BungeeCord's
`Server.sendData` has no delivery acknowledgement, so its log deliberately says
**send attempted** rather than delivered; a later valid observation is the
cryptographic evidence that Paper possessed a matching grant.

Inbound authority plugin messages are marked handled/cancelled before
validation, so they are not transparently forwarded. Under the same lifecycle
lock, the proxy verifies the carrier is the current backend for the exact
player/session/grant and then applies the bounded canonical Ed25519 verifier,
nonce replay guard, profile contract, observation sequence, cooldown, and
grant-time bounds. Only a fully verified frame advances the in-memory prior
observation snapshot.

The only current consumer of the verified value in both plugins is a
content-free MONITOR log containing player/backend, attestation ID, profile
digest, observation sequence, and signed-frame digest. No call bridges it to
the existing `ADMIN_REVIEWED` disposition authorization or executor.

Backend transition, disconnect, same-UUID physical-login replacement, session
replacement, and proxy shutdown invalidate/clear authority state. Velocity
invalidates before `ServerPreConnect`; BungeeCord invalidates when its deferred
routes enter backend-connecting state. A stale old-backend observation cannot
be accepted after that boundary.

## File and key hardening

Security-sensitive configuration and key reads use
`AuthorityFilePreflight`:

- configured key/journal paths must be non-empty relative paths that remain
  below the plugin data directory after normalization;
- the complete existing ancestor chain and leaf are inspected with
  `NOFOLLOW_LINKS` and must contain only directories plus one regular-file leaf;
- symbolic links, junctions/reparse points exposed as special objects, lexical
  escapes, and non-regular files are rejected;
- the canonical root/file relationship and path identity are checked before and
  after the read; and
- reads are size-bounded before allocation and reject growth/replacement seen
  during the read.

Limits are 64 KiB for proxy `authority.properties`, 256 KiB for Paper
`config.yml`, and 4096 bytes for each authority key file. Text configuration is
strict UTF-8. Proxy properties reject duplicate and unknown keys. Paper scans
the raw `authority` YAML subtree before trusting Bukkit's parsed configuration,
requires the authority root and its contents to use simple block-mapping
entries, and rejects duplicate root/subtree keys, tabs, unsupported/complex
mapping keys, inconsistent indentation, and unknown parsed fields.

The Paper private/public halves are decoded as Ed25519 keys, challenged with a
sign/verify probe, and checked against the configured canonical public-key
SHA-256. `ProxyIdentityStore`, Velocity `ServerIdentityStore`, and BungeeCord
`BungeeIdentityStore` all use the same preflight contract for their trust-root
or identity material: no-follow path-chain validation, a 4096-byte bound,
native-owner/private-ACL validation before and after reads, exact Ed25519
private/public pair validation, and private same-directory atomic creation when
an identity must be initialized. Paper's pinned proxy public key must match the
selected proxy's grant-signing identity; each proxy independently verifies all
backend public-key pins.

The preprovisioned journal must begin with exactly:

```text
MCACE_SERVER_AUTHORITY_ISSUANCE_JOURNAL_V3
```

followed by one LF byte. Runtime never creates or initializes this file. The
journal keeps one no-follow read/write handle and an exclusive lock for its
entire lifetime, enforces a maximum 64 MiB quota, rejects malformed, duplicate,
partial, non-increasing, or identity-changing records, and revalidates the
exact appended record after every forced append. The complete bounded file is
decoded once during startup into an in-memory recovery index; routine
`lastSequence`/`recover` lookups and appends do not re-decode historical records.
On supported Windows OpenJDK 21 it also requests `NOSHARE_DELETE` and
`NOSHARE_WRITE`; on non-Windows it requires filesystem `fileKey` identity.

On Linux/POSIX, enabled authority configuration, key, journal, identity, and pin
paths fail closed unless every protected directory at/below the plugin data root
is owned by the runtime's native effective UID with mode `0700`, and each
protected file is owned by that UID with mode `0600`. This check does not trust
the mutable Java `user.name` property. On Windows, the native NT runtime
principal must own each protected path and every directory/file DACL must be
protected, contain no inherited ACE, and contain exactly `FullControl` entries
for that principal and `SYSTEM` (with the exact directory inheritance flags and
no file inheritance flags). Broad or unverifiable DACLs fail closed. The
provisioner protects the two generated runtime private-key files for the current
user plus `SYSTEM` on Windows (or mode `0600` outside Windows), commits the
output with one directory rename, and removes a partial staging tree if that
private-key postcondition cannot be established. Operators must establish and
preserve the runtime's stricter complete directory/file isolation contract when
deploying the selected files into plugin data roots.

Formal process evidence has an additional, independent trust boundary. The V3
freeze pins an external `ED25519` supervisor public descriptor and canonical key
ID. The descriptor's exact file SHA-256 must also equal
`MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256`; a
caller-provided value cannot approve itself. The supervisor private key remains
outside the repository, provisioned runtime, capture package, logs, and standard
output.

The V4 collector does not accept a narrative PASS or operator booleans. Formal
collection is a two-phase external handoff: it first validates all raw bytes,
then atomically emits an
`MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_SIGNING_REQUEST_V1` outside the
repository/release/output roots and waits at 250 ms intervals for the requested
receipt. The request binds the exact expected receipt payload bytes, reviewed
descriptor pin and key ID, capture/operation IDs, fresh 32-byte challenge,
source/artifact commits, release JARs, and every raw/frame/provider/profile/
topology/process/journal commitment. The external signer signs those exact
bytes with its separately held Ed25519 key and atomically publishes the V1
receipt. The collector re-reads the unchanged request and validates the current
receipt before any report, binding, commit document, or package directory can
be committed. Immediate pre-existing receipts are fixture-only, not a Formal
release path.

The collector then reads
the actual protobuf `BackendAuthorityGrant` and `ServerAuthorityObservation`
frame bytes, rebuilds their signing inputs, validates Ed25519 signatures against
the frozen proxy/backend roots, verifies CRC32C/header/session/key/profile/grant
linkage, and recomputes both the grant commitment and canonical provider
evidence commitment. It independently validates the raw provider/Paper/proxy
event chain, durable journal, process incarnations/exit/cleanup, licensed Vulcan
artifact, exact release-bundle JARs, and the detached supervisor receipt.

The receipt signature covers the request's exact payload bytes, including the ordered raw evidence root, exact frame set,
provider commitment, event/process ledgers, source and artifact commits, Paper
and both proxy JAR hashes, profile/topology/key IDs, selected proxy, `MONITOR`
ceiling, zero automatic actions, capture/attempt IDs, one-time challenge,
issuance time, and expiry. Publisher replay checks reject reuse of either the
operation attempt or challenge.

The receipt expiry is the live signer-exchange deadline. The producer must
receive and validate the receipt before that deadline, and the durable package
timestamp must remain inside the signed interval. Once committed, later
publisher/readiness/tag validation checks that historical ordering and the
immutable signature; it does not compare the old exchange deadline with the
current wall clock. `-RequireCurrentlyValidReceipt` is reserved for the
immediate collection/publication acceptance stage.

## Failure and restart semantics

| Event | Required/current behavior |
| --- | --- |
| Invalid untrusted grant candidate | log; preserve the current verified grant |
| Verified new grant but journal recovery fails | remove that player's grant/lifecycle/correlation state |
| Provider callback or scheduler runtime failure | contain and log; do not escape into the provider plugin |
| Pre-journal semantic rejection | return no frame; issuer remains reusable |
| Journal I/O/identity/force/post-force uncertainty | return no frame; poison issuer/journal until close/reopen |
| Channel registration failure, including mutate-then-throw | compensate every attempted registration, then close journal/runtime |
| Quit, physical-login replacement, backend switch | clear/invalidate exact player authority state |
| Paper/Folia restart | reopen and validate the preprovisioned journal; after receiving an exact verified grant, recover sequence plus last observed/issued times for that lifecycle |
| Proxy restart | in-memory grants/prior snapshots disappear; a new exact grant is required before any observation can validate |

Journal recovery restores cooldown as well as the observation sequence. A
restart therefore cannot reset the per-lifecycle cooldown or reuse already
consumed provider evidence merely because the in-memory correlator was empty.
Recovery is bound to backend instance, player UUID, authenticated session, and
physical-login binding; unrelated or stale lifecycle records do not become a
sequence oracle for a new login.

The code-level behavior above is not yet equivalent to a completed restart
acceptance test across real Velocity/Bungee, Paper/Folia, and genuine provider
processes. That remains a release gate.

## Protocol validation boundary

`BackendAuthorityGrant` and `ServerAuthorityObservation` use packet types 21
and 22, schema version 1, an 8 KiB maximum frame, and a maximum 30-second
authority TTL/observation age. Core codecs enforce bounded/canonical protobuf
and signed-envelope encoding, reject unknown fields and noncanonical byte
representations, validate Ed25519 signatures, checksums, timestamps, key IDs,
nonces, exact lifecycle bindings, provider profiles, independent-domain quorum,
strictly increasing sequences, and cooldown.

The observation includes:

- backend instance/key ID and attestation ID;
- player, authenticated session, grant ID/commitment, physical-login binding,
  and admission transport sequence;
- strictly increasing observation sequence and bounded timestamps;
- canonical authority-profile SHA-256; and
- content-free independent provider summaries.

The proxy platform adapter, not the codec alone, proves carrier provenance and
holds the physical-login lock. Both layers are required.

## Verification commands

Use JDK 21 and the repository's strict offline dependency verification:

```powershell
$env:JAVA_HOME = "$env:USERPROFILE\.gradle\jdks\eclipse_adoptium-21-amd64-windows.2"
.\gradlew.bat `
  :mcace-core:test `
  :mcace-server-paper:test `
  :mcace-server-velocity:test `
  :mcace-server-bungeecord:test `
  --offline --dependency-verification=strict `
  --no-daemon --no-parallel --max-workers=1 --console=plain
```

Authority-focused suites include:

- core: `AuthorityFilePreflightTest`, `BackendAuthorityGrantCodecTest`,
  `BackendAuthorityRegistryTest`, `ServerAuthorityObservationCodecTest`,
  `DurableServerAuthorityIssuerTest`,
  `FileServerAuthorityIssuanceJournalTest`,
  `ProxyServerAuthorityRuntimeTest`, and
  `VerifiedServerAuthorityObservationTest`;
- Paper/Folia: `PaperServerAuthorityConfigurationTest`,
  `PaperAuthorityProviderCorrelatorTest`,
  `PaperServerAuthorityLifecycleTest`,
  `PaperServerAuthorityIssueCoordinatorTest`,
  `PaperServerAuthorityRuntimeTest`,
  `PaperServerAuthorityJournalWriterTest`, and
  `PaperServerAuthorityChannelLeaseTest`.

Run the real OpenSSL provisioning regression under both supported PowerShell
engines:

```powershell
pwsh -NoProfile -File .\scripts\test-provision-production-authority.ps1
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File .\scripts\test-provision-production-authority.ps1

pwsh -NoProfile -File .\scripts\test-production-authority-process-evidence.ps1
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File .\scripts\test-production-authority-process-evidence.ps1
```

Unit tests and controlled executable fixtures are development evidence. They
must not be relabelled as genuine provider or production-process evidence.

## Remaining production release gate

Before promoting this path beyond staged MONITOR, capture an exact-commit,
native evidence bundle that proves all of the following:

1. the exact V3 frozen provider/profile/key/topology/action-ceiling manifest
   matches the deployed files, proves distinct backend/proxy identities, pins
   one selected proxy platform per backend, and binds the independently reviewed
   external supervisor public descriptor used to sign the receipt;
2. licensed, reviewed Vulcan and the second independent provider emit genuine
   eligible events in the same physical session (not a synthetic
   `TEST_ATTESTATION_FIXTURE`);
3. Paper/Folia appends and forces the expected journal record before the exact
   observation frame is sent;
4. Velocity and BungeeCord independently accept the exact backend key/profile,
   grant, session, physical login, admission sequence, and observation sequence;
5. malformed, replayed, stale-backend, wrong-session, wrong-key, wrong-profile,
   cooldown, restart, and disconnect cases fail closed;
6. Bungee evidence distinguishes a send attempt from confirmed receipt;
7. process shutdown leaves zero MCAce-owned Java/server residue; and
8. the verified observation remains MONITOR-only with no automatic kick,
   quarantine, deny, or ban side effect;
9. the external supervisor receives the post-prevalidation V1 signing request,
   verifies its out-of-band descriptor pin and exact commitments, signs only
   its exact payload bytes, and publishes the receipt atomically inside the
   15-minute challenge/attempt validity window; and
10. `publish-native-release-evidence.ps1` revalidates the exact staged raw bytes
    and V4 release bundle and publishes an
    `MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V4` without receipt reuse.

The repository currently contains validator tests and fixtures, not a genuine
external production capture. No licensed genuine Vulcan production event or
external-supervisor Authority V4 receipt/index is retained, so the Authority
release gate remains blocked.

Only after this MONITOR evidence exists should a separate design/review decide
whether to connect `VerifiedServerAuthorityObservation` to durable trusted
authorization. Any future `LIMIT`, `QUARANTINE`, or current-connection-only
`DENY` rollout needs its own policy, false-positive, fault-injection, and
real-process acceptance gate. Permanent automatic banning remains prohibited.
