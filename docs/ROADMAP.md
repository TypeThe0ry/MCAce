# MCAce delivery roadmap

## Current execution baseline

- [x] Support exactly three Fabric targets: 1.21.11 on JDK 21 as a final remapped
  JAR, and 26.1.2/26.2 on isolated JDK 25 as final named JARs. All use Fabric
  Loader 0.19.3 and the exact API tuples in `FABRIC_COMPATIBILITY.md`.
- [x] Pass strict offline Windows A/D with Temurin 21.0.7+6, isolated Temurin
  25.0.3+9, and Gradle 9.6.1. Each run completed 118/118 tasks. Root results:
  147 suites / 681 tests / 0 failures / 0 errors / 28 skipped; modern results:
  24 / 74 / 0 / 0 / 0; combined: 171 / 755 / 0 / 0 / 28.
- [x] Generate byte-identical exact-eight LOCAL verification bundles in A/D: six
  deployables, `release-manifest.properties`, and `SHA256SUMS`. Retained evidence:
  `docs/evidence/local-build-2026-08-20.json`; `build/` remains mutable.
- [x] Reduce current exact synthetic trust to 47 root Loom-local entries plus two
  isolated modern named-Minecraft entries; no group-wide trust.
- [x] Seal the post-fix authoritative 12-case server process matrix: three
  versions × Paper/Folia × Velocity/Bungee, then `-ReportOnly`. Paper 6/6,
  Folia 6/6, Velocity 6/6, Bungee 6/6; 10 STABLE plus two Folia 26.2 BETA
  cases; cleanup zero. Retained evidence:
  `docs/evidence/server-version-process-matrix-2026-08-20.json`.
- [x] Pass server-only `platform-load-smoke.ps1 -FabricTarget <target>` for all
  three targets and prewarm/verify all required Minecraft asset objects.
- [ ] Complete the visible Fabric evidence gate for all three targets: one
  explicit-file decision and one frame decision per target, six human clicks.
- [ ] Complete the distinct real Fabric federation export/import GUI handoff.
- [ ] Rerun the licensed Vulcan structural preflight against current source, then
  pass Paper enablement and one genuine externally triggered event.
- [ ] Freeze SERVER_CONFIRMED provider/profile/key/topology/action-ceiling choices,
  wire a genuine production producer, and pass its real process matrix.
- [x] Pass current Linux run `cb6dc44ddad744b5a20dc2986c0a6d70`
  network-none with JDK 21, isolated JDK 25, strict offline verification,
  unchanged source, and exact-eight stream-byte parity with Windows A/D. The old
  JDK-21 exact-six and superseded pre-fix exact-eight records are historical.
- [ ] Review, commit, and push the current changes; retain protected exact-commit
  CI and generate a clean exact-commit `releaseBundle` candidate.

The enforcement invariants remain fixed: MONITOR default, no permanent automatic
BAN, DENY current connection only, CLIENT_REPORTED never authorizes a high-impact
action, and Cloud/Portal/PostgreSQL/Launcher remain frozen outside the product.

## Phase 1 — trustworthy foundation (complete)

- Versioned Protobuf protocol and signed binary envelope
- Replay-resistant session lifecycle
- Explainable, policy-driven risk scoring
- Loader-neutral client integrity manifest
- Fabric bootstrap for the exact 1.21.11, 26.1.2, and 26.2 targets with
  asynchronous scoped mod scanning
- SDK plus Paper and Velocity adapter foundations
- Unit tests and documented trust boundaries

Exit criteria: root/server modules compile on Java 21, isolated modern Fabric
modules compile on Java 25, cryptographic and replay tests pass, and no admission
decision relies on an unverified client assertion.

## Phase 2 — Level 1 VERIFIED (complete)

- [x] Fabric 1.21.11 remapped client plus 26.1.2/26.2 named clients and the
  common custom-payload handshake
- [x] Velocity channel challenge, authentication timeout, monitor mode, and opt-in limited routing
- [x] Persistent Ed25519 server identity and mandatory client public-key pins
- [x] End-to-end protocol tests for known-good, unpinned, replayed, and timed-out sessions
- [x] Signed server policy documents, expiry, anti-rollback client cache, and persisted renewal
- [x] Resource-pack, shader-pack, and explicitly consented configuration manifests
- [x] Root-authorized delegated policy signing-key rotation and revocation enforcement
- [x] Optional PostgreSQL-backed sessions, provenance-aware events, and signed append-only evidence metadata
- [x] Separate-process loopback runtime protocol network with known-good and deliberately malformed clients
- [x] Root-signed, expiring Velocity-to-Paper admission snapshots with backend replay protection
- [x] Historical Velocity/Paper process-load and development-client handshake
  foundations with explicit key pin and missing-pin fail-closed behavior; current
  release process coverage is the 12-case matrix above
- [ ] Current final-artifact Fabric GUI → Velocity → Paper consent/evidence route
  for each of the three supported targets

## Preserved Cloud control-plane foundation (frozen outside the product roadmap)

- [x] Ed25519 server authentication API and scoped short-lived access tokens
- [x] Risk ingestion with cloud-owned weights and explicit observation provenance
- [x] Signed evidence metadata receipts and ordered signed revocation feed
- [x] Transactional append-only operator audit for revocation changes
- [x] Provenance-aware player timeline plus transactional review and appeal workflow
- [x] Repository foundations for operator dashboard and player appeal authentication/notifications; production deployment is optional
- [x] Immutable risk-policy versions, deterministic staged rollout/rollback, metrics, and reviewed false-positive monitoring
- [x] Grim typed event adapter, bounded correlation pipeline, and authenticated Cloud delivery
- [x] Prepare a local-only licensed Vulcan structural API preflight with synthetic contract tests, sanitized hash/version/accessor reporting, no artifact copying, no path retention, and fixed `paper_process_coverage=false`
- [x] Run the historical local-only structural preflight and ReportOnly revalidation against an operator-supplied exact-hash licensed Vulcan 2.9.0 JAR; retained evidence is `docs/evidence/vulcan-licensed-api-preflight-2026-08-13.json`, is explicitly `STRUCTURAL_PREFLIGHT_ONLY`, and was valid for its contemporaneously bound source snapshot
- [ ] Rerun the licensed Vulcan structural preflight and ReportOnly binding against the current source; freshness correctly rejects the retained historical record after source-manifest drift
- [x] Add a default-deny isolated Paper enablement harness that cannot run without reviewed Vulcan/Paper/MCAce hashes, explicit temporary Paper-remap permission, and `-NetworkPolicy DenyAll` plus an operator OS/network-isolation attestation; it remains unexecuted and its schema keeps real behavior-event delivery false
- [x] Add a separate default-deny `vulcan-genuine-event-smoke.ps1` gate that forbids synthetic event dispatch, requires reviewed artifact/prepared pins plus external-trigger/no-synthetic attestations, and retains only a content-free exact-player-match result; the gate remains unexecuted
- [ ] Complete Paper plugin enablement and real behavior-event delivery against the licensed Vulcan artifact; structural preflight is not runtime or release-ready proof, and the proprietary artifact cannot be downloaded or bundled by MCAce
- [x] PostgreSQL-coordinated multi-instance replay state and externally published signed audit heads

## Re-scoped platform delivery — Mod + plugins

- [x] Fabric 1.21.11 client, final remap artifact, Java 21, signed custom-payload handshake
- [x] Fabric 26.1.2 and 26.2 clients, final named artifacts, isolated Java 25
- [x] Target-specific immutable build-ID and metadata contracts
- [x] Velocity proxy plugin with monitor/limited-route modes
- [x] BungeeCord proxy plugin using the shared handshake/admission core
- [x] Paper backend plugin consuming signed admission snapshots
- [x] Paper/Folia context publisher plus Velocity/Bungee shadow-only evaluator
- [x] Folia-safe global/region/entity scheduling and plugin metadata
- [x] Refresh and seal the exact 12-case 1.21.11/26.1.2/26.2 server process
  matrix against the post-fix source and deployables
- [x] Bounded manifest fragmentation/reassembly and heartbeat/session health
- [ ] Visible GUI/framebuffer evidence consent for all three final artifacts
- [ ] Real Fabric federation GUI handoff

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
- [x] Retain the historical August 13 opt-in Proxy + three-Paper 8/8 advisory-origin guard matrix: all Velocity/Bungee `MONITOR_LIMIT` and configured `LIMITED_ROUTE` LIMIT, QUARANTINE, and DENY requests proved that an exact-hash `CLIENT_REPORTED` match remained on lobby with no route lifecycle or connection close; retained aggregate evidence: `docs/evidence/client-reported-advisory-2026-08-13.json`.
- [x] Retain both historical Velocity/Bungee configured `LIMITED_ROUTE` DENY advisory-origin cases as part of that eight-case aggregate, proving that the tested `CLIENT_REPORTED` DENY path neither routed nor closed the current lobby connection.
- [x] Rerun the full advisory-origin matrix against the current source and exact proxy artifacts for 1.21.11, 26.1.2, and 26.2 (24/24); current committed evidence: `docs/evidence/disposition-current-2026-08-21.json`.
- [x] Retain the historical August 13 6/6 real-process `ADMIN_REVIEWED` exact-hash action matrix under `UUID_CONTEXT_COMMITMENT_V3`, with distinct reversible LIMIT/QUARANTINE routes and current-connection-only DENY followed by a clean independent-session reconnect; retained aggregate evidence: `docs/evidence/trusted-disposition-v3-2026-08-13.json`.
- [x] Rerun the `ADMIN_REVIEWED` process matrix against the current source and exact proxy artifacts for 1.21.11, 26.1.2, and 26.2 (18/18); current committed evidence: `docs/evidence/disposition-current-2026-08-21.json`.
- [x] Implement the default-disabled `SERVER_CONFIRMED` Phase 1 protocol library: bounded canonical wire schema/codecs; exact backend/key registry; canonical profiles binding provider ID/domain/version/family/threshold, quorum, shared window, and cooldown; live-verified-grant plus same-lifecycle-lock prior-snapshot validation; and a package-confined narrow token carrying the exact signed-frame SHA-256.
- [x] Implement and harden the Phase 2.5 durable-issuance slice without creating a producer: the operator preprovisions the regular content-free Paper/Folia journal with its fixed header and protected directory; runtime has no create or initialize path. The public preflight is read-only, returns the exact header bytes, and never changes the supplied path. The package-private abstract journal contract forces every implementation to define `lastSequence` rather than inheriting zero. The file implementation holds one long-lived handle and exclusive lock, uses OpenJDK `NOSHARE_DELETE`/`NOSHARE_WRITE` on Windows or a required non-null `fileKey` on non-Windows, repeats no-follow path identity checks, and performs same-handle decode, append, force, and re-decode before the public issuer returns a non-forgeable durable token. Journal I/O/identity/post-force failure poisons the issuer until reopen; pre-journal semantic rejection does not. `recover(VerifiedGrant)` returns a typed, non-externally-constructible `RecoveredServerAuthoritySequence`, and every durable token binds the verified grant, lifecycle, backend key, and time window. The raw signer is package-private. Paper instantiates a default-disabled lifecycle whose prepare returns a unique lease capability, whose commit requires the matching durable token, and whose abort permits a fresh retry; it retains nothing while disabled. This is not a pure-JDK guarantee against a local administrator, weak ACLs, or mutation after return.
- [x] Add the Phase 2.6 package-private inert Paper issuance coordinator. It enforces exact request/lease/grant precheck -> journal-derived next sequence and force -> exact durable-token commit; raw frame access remains package-private to core and is not exposed to Paper. Sequence drift removes lifecycle state and requires fresh typed recovery; uncertain I/O or post-durability commit failure poisons the coordinator instead of aborting/retrying. `MCAcePaperPlugin` does not instantiate it, and there is still no authority channel, configuration, provider, sender, trusted-authorization wiring, executor, producer process evidence, or release claim.
- [x] Pass the JDK 21 offline authority directed selections: 8 suites, 51 tests, zero failures/errors, and one host-capability symlink skip. The current whole-repository root build covers Phase 2.6 at 147 suites and 681 tests with zero failures/errors; the isolated modern build adds 24 suites and 74 tests, for 171 suites and 755 tests combined.
- [ ] Establish and process-test a genuine `SERVER_CONFIRMED` artifact/behavior authorization producer under [the backend-authority contract](SERVER_CONFIRMED_AUTHORITY.md); Paper/Folia world/game-mode shadow context is intentionally not that producer.

Evidence protocol/unit coverage is not a real Minecraft UI or proxy process smoke.
That end-to-end evidence-flow smoke remains a release gate; no screenshot alone
may become a cheat conclusion. Fabric evidence remains `CLIENT_REPORTED` and cannot
independently trigger punishment. The client/common/Fabric suites cover ACK
sequencing, resize/generation cancellation, buffer clearing, final-artifact
identity, and the Java 21/25 target split.

The old 1.21.1/1.21.4 preparation runs and wrappers are retained only as
historical diagnostics. Their Paper 1.21.1-133, BungeeCord 2028, and Folia
1.21.4-6 ALPHA pins are not current release inputs. The August 20
three-version process evidence is
`docs/evidence/server-version-process-matrix-2026-08-20.json`.

The final post-fix source/JAR/asset/prepared-tree-bound three-version raw-peer
matrix reached
accepted `AUTH_RESULT`, accepted backend admission, and
`backend_context_shadow_audit=true` in all 12 cases, with no remaining run
process. The peer is offline, loopback-only, and not a standalone client. These
results do not cover real Fabric GUI consent, Mojang/Microsoft online-mode
identity, public-network deployment, or production forwarding configuration.

The retained disposition advisory-origin aggregate evidence is:

- Velocity + Bungee, eight client-reported guard cases, including DENY on both
  proxies: `docs/evidence/client-reported-advisory-2026-08-13.json`

It proves lobby-only behavior, zero route lifecycle, and no connection close for
client-reported LIMIT/QUARANTINE/DENY requests in MONITOR and LIMITED_ROUTE
configurations.

The retained trusted-disposition V3 aggregate evidence is:

- Velocity + Bungee, six administrator-reviewed exact-hash actions:
  `docs/evidence/trusted-disposition-v3-2026-08-13.json`

It records V3 durable authorization before execution, distinct successful LIMIT/QUARANTINE routes,
current-connection-only DENY, and a clean verified-lobby reconnect for the same offline identity
under a new session, and declares `UUID_CONTEXT_COMMITMENT_V3`. This is
`ADMIN_REVIEWED` coverage only; a real-process `SERVER_CONFIRMED` artifact source and
a real Fabric GUI/framebuffer remain open release gates.

The repository's default-disabled SERVER_CONFIRMED canonical wire/verifier,
Phase 2.5 durable issuance, and Phase 2.6 inert Paper coordinator do not change
that result. Exact profile, live-grant, prior-snapshot/cooldown/sequence,
signed-frame SHA, typed grant-bound recovery, append-and-force journal, issuer and
coordinator poison, exact precheck, and Paper lease/commit/abort tests are green in
the 8-suite/51-test directed selections. Raw frame access stays package-private to
core. No proxy or backend instantiates the coordinator, registers the authority
channel, supplies authority configuration or production providers, sends an
authority frame, or wires trusted authorization/execution. No real-process producer
gate or release coverage exists. The current whole-repository build covers the
default-disabled library but does not substitute for producer process evidence.

## Future ecosystem work within the current scope

- [x] Stable read-only third-party SDK 1.0, capability negotiation, cross-classloader JDK-only bridge, and three-platform compatibility suite
- [x] Cross-network federation threat model, reciprocal operator-pin contract, per-target one-time player consent state machine, privacy boundary, and executable attack/release matrix
- [x] Versioned four-message federation protocol: explicit source-operator request, signed Fabric consent, source-signed client-carried grant, target-session PoP presentation, dual offline key fingerprints, strict <=5 minute bounds, final-step replay consumption, and protocol attack corpus
- [x] Complete disabled-by-default federation runtime under `docs/FEDERATION.md`: source operator issue/audit, distinct Fabric source-export and target-import `Allow once` screens, bounded in-memory grant/key vault, independent target-local `VERIFIED` prerequisite, exact prepared-presentation reservation, proxy observation-only store, and cleanup/noninterference tests; no source-target channel, HTTP/socket, token broker, Cloud, or instant remote revocation.
- [x] Make federation audit fail closed: successful issue/grant/observation waits for a bounded durable worker acknowledgement; queue admission is never durable success; background/file/timeout faults are sticky, clear ephemeral state, disable federation only, and surface content-free health in both proxy commands. Unit and fault-injection gates pass.
- [x] Durably retain the historical August 13 schema-2 federation process record in `docs/evidence/federation-durable-audit-2026-08-13.json`: the tested matrix passed 4/4 plus `-ReportOnly`, with healthy source/target audit, unchanged local trust/risk/Paper admission, and zero residual processes. The record binds older proxy artifacts/source, so it is not current release evidence. It records `residual_reacceptance=true`, `durable_replay_protection=false`, and `fabric_gui_coverage=false`.
- [ ] Rerun the raw-peer federation matrix and target-restart process gate against the current source and exact proxy artifacts.
- [x] Implement the default-disabled, fail-closed, three-target V2 Fabric
  federation wrapper plus source-export/target-import screens and six exact
  runtime markers; its static contract tests pass under PowerShell 7 and Windows
  PowerShell 5.
- [ ] Pass the remaining real Fabric federation gate: human-visible source-export
  `Allow once`, disconnect/direct-connect to the exact target, a distinct visible
  target-import `Allow once`, actual client-carried transition, a live target
  session through expiry, cleanup, and GUI privacy evidence. Static and raw-peer
  evidence do not claim this coverage.

Additional client loaders are outside the current Fabric-first product roadmap.

The authoritative product scope and trust semantics are defined in
`docs/PRODUCT_SCOPE.md`.
