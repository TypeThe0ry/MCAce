# Detection, disposition, and evidence contract

## Status

This document defines the MCAce detection safety contract. The current
implementation provides signed policy structures, a strict protocol-to-core
compiler, one platform-neutral proxy evaluator, neutral Fabric artifact
metadata, proxy-safe authenticated manifest fragmentation, and live
Velocity/Bungee policy adapters. Both proxies now derive and evaluate initial
  artifact observations from the complete authenticated manifest, but the result
  is audit-only: it does not alter admission or routing. Fabric can now collect one
  Minecraft render frame only after a visible, per-request `Allow once` decision.
Operating-system window and desktop capture remain unsupported, zero-content, and
disabled. The repository has an explicit opt-in encrypted content-store control,
but no raw-image reviewer retrieval UI; default operation discards raw bytes.

After an accepted authentication result, Fabric may also send an optional complete
artifact-observation refresh no more often than every five minutes. It rescans only
the same signed-policy integrity scopes; it never accepts server-supplied paths,
does not scan private files, and is not required for a session to remain verified.
The transfer is separately signed and session-bound, has a 256 KiB / 16-chunk /
512-entry ceiling, and binds its strict update sequence, authentication-time
manifest root, prior/current aggregate roots, policy digest/sequence, and an
observed-at value no older than one minute. The client advances that chain only
after every transfer fragment has actually been sent. Velocity and Bungee validate
the full snapshot root again, derive all provenance as `CLIENT_REPORTED` / `LOW`,
and run an asynchronous audit-only evaluation. Rejection, replay, expiry, scope
escape, or queue saturation never changes an already `VERIFIED` admission.

Each proxy also keeps a bounded, durable dynamic-observation audit journal for
operations. Its entries contain only player UUID, observation/evaluation times,
observation and consistency-issue counts, aggregate action counts, and policy
refresh state. They contain no paths, filenames, artifact identifiers, hashes,
rule IDs, raw manifests, screenshots, or other private content. Administrators
with `mcace.admin.audit` may use `/mcaceobservation status` or
`/mcaceobservation player <uuid> [1-100]`; both commands are strictly read-only
and have no risk, admission, or disposition effect.

The opt-in real-process Fabric evidence smoke uses the ordinary signed proxy
request and the same consent screen. It waits for a human `Allow once` action,
then verifies bounded Begin/Chunk/Commit upload and the server-signed `COMPLETE` ACK,
and Velocity's content-free audit line. It has no automatic consent, desktop or
window capture, mouse automation, or account-authentication bypass.

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

`CLIENT_REPORTED`, `INFERRED`, and `UNAVAILABLE` observations are never a sole
basis for a permanent ban. The product has no automatic `BAN` disposition.

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
| `GAME_RENDER_FRAME` | One Minecraft-rendered frame. | Fabric, visible per-request consent only. |
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

Velocity and BungeeCord must evaluate the same inputs through one shared proxy
runtime. Paper/Folia verifies the resulting short-lived proxy snapshot and only
executes the signed disposition; it does not independently reinterpret policy.

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

Initial Mod, resource-pack, shader-pack, and consented configuration observations
come from the signed `AuthRequest` scope manifests. A second client-provided list
cannot replace this source or omit an entry from it. Fabric Mod ID/version metadata
is accepted only when its path, size, and SHA-256 reconcile with the corresponding
authorized `mods` scope entry. Client-provided signer and arbitrary metadata fields
are not made available to policy selectors.

Every plugin-message frame is capped at 30 KiB for the Velocity/Bungee common
transport budget. Small authentication requests retain the legacy packet. Larger
requests use individually signed `PAYLOAD_BEGIN`, ordered `PAYLOAD_CHUNK`, and
`PAYLOAD_COMMIT` envelopes with 16 KiB chunks, a 1 MiB/64-chunk total limit,
content hash, Merkle root, session ID, nonce replay protection, sequence, and a
one-minute receiver lifetime. Only one transfer may be active per session.

The proxy fixes the derived provenance to `CLIENT_REPORTED`, confidence to `LOW`,
and foundation-security status to false. Evaluation runs through a bounded
asynchronous audit queue; saturation drops audit work and never changes the
player's authentication result. Dynamic post-authentication observations remain
unsupported and are rejected explicitly rather than treated as processed.

Fabric artifact observations are derived only from the already authorized
`mods`, `resourcepacks`, and `shaderpacks` manifests. They are always
`CLIENT_REPORTED` with low confidence. A bounded read of `fabric.mod.json` may
provide Mod ID/version; invalid metadata becomes `unknown`. Resource and shader
pack filenames are classification inputs, never proof of X-ray behavior.

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
  out-of-scope, and oversized snapshots while a verified admission remains intact.
