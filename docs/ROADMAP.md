# MCAce delivery roadmap

## Phase 1 — trustworthy foundation (complete)

- Versioned Protobuf protocol and signed binary envelope
- Replay-resistant session lifecycle
- Explainable, policy-driven risk scoring
- Loader-neutral client integrity manifest
- Fabric 1.21.1 bootstrap with asynchronous scoped mod scanning
- SDK plus Paper and Velocity adapter foundations
- Unit tests and documented trust boundaries

Exit criteria: all modules compile on Java 21, cryptographic and replay tests pass,
and no admission decision relies on an unverified client assertion.

## Phase 2 — Level 1 VERIFIED (complete)

- [x] Fabric 1.21.1 Loom/remapped client and custom-payload handshake
- [x] Velocity channel challenge, authentication timeout, monitor mode, and opt-in limited routing
- [x] Persistent Ed25519 server identity and mandatory client public-key pins
- [x] End-to-end protocol tests for known-good, unpinned, replayed, and timed-out sessions
- [x] Signed server policy documents, expiry, anti-rollback client cache, and persisted renewal
- [x] Resource-pack, shader-pack, and explicitly consented configuration manifests
- [x] Root-authorized delegated policy signing-key rotation and revocation enforcement
- [x] Optional PostgreSQL-backed sessions, provenance-aware events, and signed append-only evidence metadata
- [x] Separate-process loopback runtime protocol network with known-good and deliberately malformed clients
- [x] Root-signed, expiring Velocity-to-Paper admission snapshots with backend replay protection
- [x] Real Velocity/Paper process-load smoke with explicit key pin and missing-pin fail-closed gate
- [x] Full Fabric client → Velocity → Paper player-flow smoke network

## Preserved Cloud control-plane foundation (frozen outside the product roadmap)

- [x] Ed25519 server authentication API and scoped short-lived access tokens
- [x] Risk ingestion with cloud-owned weights and explicit observation provenance
- [x] Signed evidence metadata receipts and ordered signed revocation feed
- [x] Transactional append-only operator audit for revocation changes
- [x] Provenance-aware player timeline plus transactional review and appeal workflow
- [x] Repository foundations for operator dashboard and player appeal authentication/notifications; production deployment is optional
- [x] Immutable risk-policy versions, deterministic staged rollout/rollback, metrics, and reviewed false-positive monitoring
- [x] Grim typed event adapter, bounded correlation pipeline, and authenticated Cloud delivery
- [ ] Licensed Vulcan runtime compatibility gate (isolated adapter implemented; proprietary API cannot be bundled)
- [x] PostgreSQL-coordinated multi-instance replay state and externally published signed audit heads

## Re-scoped platform delivery — Mod + plugins

- [x] Fabric 1.21.1 client Mod and signed custom-payload handshake
- [x] Velocity proxy plugin with monitor/limited-route modes
- [x] BungeeCord proxy plugin using the shared handshake/admission core
- [x] Paper backend plugin consuming signed admission snapshots
- [x] Folia-safe global/region/entity scheduling abstraction and plugin metadata
- [x] Real BungeeCord and Folia process-load smoke with loopback, pin, and cleanup gates
- [x] Test-only raw Minecraft 1.21.1 peer through Velocity/BungeeCord + Paper reaching accepted `AUTH_RESULT` and `VERIFIED`/`VERIFIED`/risk 0
- [ ] Real Fabric GUI/framebuffer evidence-consent and upload smoke; the raw peer is not an independent client product
- [x] Real Folia offline player-flow, signed admission expiry, PlayerQuit cleanup, and live entity/global scheduler validation
- [x] Shared proxy adapter transport contract and Velocity/Bungee compatibility suite (player-only gate, fixed channels, heartbeat/evidence routing, signed admission pin verification, disconnect cleanup, and monitor-mode non-enforcement)
- [x] Bounded manifest fragmentation/reassembly for the lowest common proxy payload budget
- [x] Signed heartbeat with ACTIVE/STALE/MISSING health transitions and monitor-only audit trail
- [x] Optional session-only MISSING heartbeat control (disabled by default; consecutive MISSING only; NOTICE/LIMITED_ROUTE only; reversible and never a ban)
- [x] Explicit Fabric compatibility matrix and signed release-build identity; only 1.21.1 is currently supported

## Retained legacy extensions — frozen and not part of delivery

- [x] Optional Cloud control-plane, PostgreSQL audit, dashboard, and appeal-portal foundations
- [x] Optional signed Launcher manifest/atomic-update research module

No Launcher-to-Mod session evidence, Windows Agent, separate desktop client, or
mandatory Cloud dependency will be added under the current goal. Existing source
is preserved solely to avoid deleting prior work.

The staged deployment and rollback path is documented in
[`MIGRATION.md`](MIGRATION.md). It keeps Cloud, Launcher, and PostgreSQL outside
the supported trust path while preserving their existing source and data.

## Detection, disposition, and evidence delivery

- [x] Provenance-aware detection facts and non-punitive disposition vocabulary
- [x] Signed/versioned disposition policy schema with expiry, chain hash, rollout stage, and structural safety validation
- [x] Deterministic explainable core evaluator with foundation-security isolation and no automatic ban action
- [x] Velocity/Bungee session-bound, bounded, idempotent disposition executor with `MONITOR` default, sanitized hints, explicit distinct limited/quarantine routing, and current-connection-only DENY
- [x] Explicit game-frame/window/desktop evidence scopes and non-punitive decline/unavailable outcomes
- [x] Bounded Begin/Chunk/Commit evidence protocol plus deterministic client chunk/hash/Merkle primitives
- [x] Protocol-to-core policy compiler plus platform-neutral Velocity/Bungee evaluation runtime
- [x] Wire the shared runtime into both proxy plugin lifecycles and one persisted signed-policy source
- [x] Fabric Mod/resource/shader neutral artifact observations from policy-authorized manifests
- [x] Bounded textproto authoring, root-signed atomic publication, history, and per-player exceptions
- [x] Public-market detection catalog schema, explicit operator selections, safe preview/validate/list/publish commands, and false-positive controls
- [x] Server-derived resource/shader directory content roots with exact-file fallback and client metadata ignored
- [x] Authenticated manifest transport/derivation and observation-only proxy evaluation lifecycle
- [x] Post-authentication dynamic observation updates with bounded complete snapshots, change binding, and audit-only proxy evaluation
- [x] Paper/Folia backend-local signed-admission adapter with MONITOR default, one-shot LIMITED notice, and explicit current-connection-only BLOCKED action; proxy adapters remain the owner of rule-level NOTICE/WARN/LIMIT/QUARANTINE/DENY
- [x] Game-render-frame per-request consent UI, in-memory capture, paced signed upload, and shared proxy reassembly
- [x] Explicit retention disclosure, legacy default-discard semantics, 24-hour ceiling, and opt-in bounded AES-GCM storage with status/delete/audit controls
- [x] Plugin-embedded, default-off loopback reviewer for retained game-render frames with console-only, single-use URLs, v2 authenticated storage, bounded PNG validation, and content-free audit
- [x] Window/desktop capture remains unsupported, zero-content, and disabled; no current product path collects or retains it
- [ ] Opt-in real Proxy + three-Paper disposition matrix: Velocity now has independently reported synthetic exact-hash `MONITOR_LIMIT`, enforced LIMIT, and enforced QUARANTINE process cases; Bungee remains Phase 1 only. The Velocity DENY reconnect harness now has content-free pre-reconnect lifecycle gates and fixed stage/termination reporting, but remains incomplete until a post-fix real rerun passes. WARN/other MONITOR cases, Bungee Phase 2, selector rejection, and hostile admission injection remain explicitly unproved.

Evidence protocol/unit coverage is not a real Minecraft UI or proxy process smoke.
That end-to-end evidence-flow smoke remains a release gate; no screenshot alone
may become a cheat conclusion. Fabric evidence remains `CLIENT_REPORTED` and cannot
independently trigger punishment. The client-side ACK sequence, resize/generation
cancellation, and buffer clearing are covered by 49 common/Fabric tests.

The recorded platform process gates are:

- Velocity + Paper: `build/platform-smoke/runs/20260808T171235524Z/report.json`
- BungeeCord + Paper: `build/platform-smoke-bungee/runs/20260808T173618257Z/report.json`
- Folia + Paper plugin: `build/platform-smoke-folia/runs/20260808T202505461Z/report.json`

All three reports are `passed` with loopback-only endpoints, independent run
roots, and cleanup at zero. The Folia record requested 1.21.1 but tested official
1.21.4-6 `ALPHA` because no exact 1.21.1 artifact was available; global scheduling
was exercised live; a bounded offline raw player also exercised signed admission,
global expiry, and PlayerQuit/entity cleanup. It does not prove online-mode or
production proxy forwarding. A separate test-only raw Minecraft 1.21.1 peer reached accepted `AUTH_RESULT` and Paper
`VERIFIED`/`VERIFIED`/risk 0 in the following passing runs:

- Velocity modern forwarding: `build/runtime-player-probe/runs/velocity-2026-08-08T21-05-56-077744500Z/report.json` and `report.md`
- BungeeCord IP forwarding: `build/runtime-player-probe/runs/bungee-2026-08-08T21-05-11-821390700Z/report.json` and `report.md`

Both reports have `remaining_run_processes=[]`. The corresponding absolute report
roots are under `C:\Users\TT\Documents\GitHub\MCAce\build\runtime-player-probe\runs\`.
This peer is a test probe, not a standalone client, and does not cover real Fabric
GUI/framebuffer capture, Mojang/Microsoft online-mode authentication, or
public-network deployment. The recorded gates do exercise Velocity modern and
Bungee IP forwarding against Paper in offline loopback mode.

## Future ecosystem work within the current scope

- [x] Stable read-only third-party SDK 1.0, capability negotiation, cross-classloader JDK-only bridge, and three-platform compatibility suite
- [x] Cross-network federation threat model, reciprocal operator-pin contract, per-target one-time player consent state machine, privacy boundary, and executable attack/release matrix
- [x] Versioned four-message federation protocol: explicit source-operator request, signed Fabric consent, source-signed client-carried grant, target-session PoP presentation, dual offline key fingerprints, strict <=5 minute bounds, final-step replay consumption, and protocol attack corpus
- [x] Complete disabled-by-default federation runtime under `docs/FEDERATION.md`: source operator issue/audit, Fabric `Allow once` implementation and bounded in-memory grant/key vault, independent target-local `VERIFIED` prerequisite, proxy observation-only store, and cleanup/noninterference tests; no source-target channel, HTTP/socket, token broker, Cloud, or instant remote revocation. The four real proxy pairs passed in `build/runtime-federation-matrix/runs/` on 2026-08-09.
- [ ] Pass federation release gates: four Velocity/Bungee source-target pairs, real Fabric client-carried handoff, source-disconnect-after-grant, target-restart residual replay, capture-first PoP attacks, privacy scan, and proof that trust/risk/disposition/evidence behavior is unchanged

Additional client loaders are outside the current Fabric-first product roadmap.

The authoritative product scope and trust semantics are defined in
`docs/PRODUCT_SCOPE.md`.
