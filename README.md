# MCAce

MCAce (Minecraft Advanced Client Environment) is a defensive trust and admission
platform for modern Minecraft networks. It combines signed client attestations,
integrity manifests, replay-resistant sessions, explainable risk scoring, and
server-side enforcement hooks.

MCAce is **not** a replacement for a behavior anti-cheat. Client evidence is one
input to a layered decision and must never be the sole reason for an irreversible
punishment.

The product is a Fabric client Mod plus Velocity/BungeeCord and Paper/Folia
server plugins. Legacy Cloud, portal, PostgreSQL, and Launcher source is retained
to avoid deleting earlier work, but is frozen outside the current delivery
roadmap and cannot become a prerequisite or alternate trust path. See
[docs/PRODUCT_SCOPE.md](docs/PRODUCT_SCOPE.md).

## Current milestone: Fabric Mod + multi-platform server plugins

- Protobuf protocol contract and Ed25519-signed envelopes
- Timestamp, checksum, payload-size, and nonce replay validation
- Session state machine and explainable risk engine
- Versioned, capability-negotiated, read-only Java SDK with a JDK-only bridge across isolated plugin class loaders
- Restricted Minecraft-directory integrity scanner
- Velocity and BungeeCord proxy adapters plus a Paper/Folia backend adapter
- Fabric 1.21.1 remapped mod with signed `mcace:handshake` payloads
- Velocity challenge/authentication flow with timeout and optional limited routing
- Signed, expiring server policies with client anti-rollback/equivocation cache
- Pinned-root authorization, automatic delegated policy-key rotation, and old-key revocation
- Optional PostgreSQL session/risk audit storage and Ed25519-signed append-only evidence metadata
- Policy-driven `mods`, `resourcepacks`, `shaderpacks`, and consented `options.txt` manifests
- Separate-JVM loopback runtime network covering known-good and controlled malformed clients
- Root-signed proxy-to-backend admission snapshots with bounded refresh/expiry
- Folia-aware global, region, and entity scheduling with explicit plugin metadata
- Signed, independently versioned detection/disposition policy schema and deterministic explainable policy engine
- Operator-authored detection catalog with strict preview/validate/list/publish gates, explicit selections, and signed atomic publication
- Velocity/Bungee session-bound, bounded, idempotent disposition executors with `MONITOR` as the safe default; high-impact actions remain gated by explicit routing mode and verified session state
- Bounded Begin/Chunk/Commit evidence transport with Fabric-only `GAME_RENDER_FRAME` per-request consent and shared proxy reassembly; `GAME_WINDOW`/`DESKTOP` are unsupported zero-content outcomes, and raw storage defaults to discard
- Real Velocity 3.5.1/Paper 1.21.1, BungeeCord/Paper, and Folia process-load smoke with missing-pin fail-closed coverage; raw-peer and Fabric GUI/evidence coverage remain explicitly bounded as documented below
- Fabric 1.21.1 player-flow smoke through Velocity into Paper with VERIFIED/risk 0 assertions; the test-only raw Minecraft peer is not an independent client product
- Fabric evidence ACK sequencing, resize/generation cancellation, and buffer clearing covered by 49 common/Fabric tests
- Grim typed behavior adapter plus isolated Vulcan bridge, bounded correlation, and an optional Cloud-delivery foundation
- Cross-instance atomic challenge consumption and leased external signed audit-anchor publication
- Role-gated operator dashboard and UUID-bound player appeal portal with one-time handoffs

The required deployment path is the Fabric Mod and Velocity/BungeeCord plus
Paper/Folia plugins. Legacy Cloud, PostgreSQL, Launcher, and portal foundations
are preserved but frozen; no Launcher, Agent, separate desktop client, or
mandatory Cloud work belongs to the current roadmap. Their presence is also not
evidence that a production raw-image reviewer UI is available. The current
evidence path is limited to signed, per-request Fabric game-render consent, a
bounded transfer, and an explicitly opt-in encrypted store. A declined or
unsupported request is not a cheat conclusion. The licensed Vulcan runtime
compatibility gate remains in progress.

See [docs/ROADMAP.md](docs/ROADMAP.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md),
[docs/SECURITY.md](docs/SECURITY.md), [docs/OPERATIONS.md](docs/OPERATIONS.md), and
[docs/RUNTIME_TESTING.md](docs/RUNTIME_TESTING.md). Third-party integration is
documented in [docs/SDK.md](docs/SDK.md). Platform-process validation is
documented in [docs/PLATFORM_TESTING.md](docs/PLATFORM_TESTING.md). Legacy Cloud
and Launcher documentation is retained only with the frozen source and is not a
current product plan.
For a staged, reversible move from legacy deployments to the supported Mod +
plugin topology, see [docs/MIGRATION.md](docs/MIGRATION.md).
Behavior adapters and their false-positive controls are documented in
[docs/BEHAVIOR_INTEGRATIONS.md](docs/BEHAVIOR_INTEGRATIONS.md).
Detection dispositions, screenshot scopes, and evidence safety gates are defined
in [docs/DETECTION_AND_EVIDENCE.md](docs/DETECTION_AND_EVIDENCE.md).
Public cheat/X-Ray/automation research, false-positive controls, and the safe
catalog authoring workflow are documented in
[docs/DETECTION_CATALOG.md](docs/DETECTION_CATALOG.md).
The exact supported Fabric tuple and release build-ID procedure are recorded in
[docs/FABRIC_COMPATIBILITY.md](docs/FABRIC_COMPATIBILITY.md).

## Recorded platform smoke gates

The final recorded platform runs use independent run roots, ephemeral loopback
listeners, and cleanup that leaves zero run-owned processes. The default
Velocity/Paper smoke does not start Fabric or inspect an existing user process;
the client variant is explicit and must be requested with `-WithFabricClient`.

| Gate | Command and report | Fixed official artifacts and SHA-256 | Scope actually proved |
| --- | --- | --- | --- |
| Velocity + Paper | `./scripts/platform-load-smoke.ps1`<br>`build/platform-smoke/runs/20260808T171235524Z/report.json` | Velocity 3.5.1-615: `b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3`<br>Paper 1.21.1-133: `39bd8c00b9e18de91dcabd3cc3dcfa5328685a53b7187a2f63280c22e2d287b9`<br>PaperMC Fill object URLs recorded in the report | Pin load, missing-pin fail closed, loopback readiness, graceful cleanup; no player in this run |
| BungeeCord + Paper | `./scripts/bungee-paper-load-smoke.ps1`<br>`build/platform-smoke-bungee/runs/20260808T173618257Z/report.json` | BungeeCord build 2028: `45a5aa27b9f2446c320447148913aee5673ec23ddf30c81d6dafa9dd910a91eb`<br>Paper 1.21.1-133: `39bd8c00b9e18de91dcabd3cc3dcfa5328685a53b7187a2f63280c22e2d287b9`<br>Spigot Jenkins and PaperMC Fill URLs recorded in the report | Pin compatibility, signed-admission fixtures, loopback readiness, cleanup; no real player, live handshake, or live backend forwarding |
| Folia + Paper plugin | `./scripts/folia-process-smoke.ps1`<br>`build/platform-smoke-folia/runs/20260808T202505461Z/report.json` | Requested Folia 1.21.1 had no official build; tested official Folia 1.21.4-6 `ALPHA`: `dcf2333211c1468c8eddc482bc8549600818cc661a709124a79c752f8fa2ac3a`<br>PaperMC Fill API/object URL recorded in the report | Missing-pin fail closed; a bounded offline raw peer completed login/configuration, delivered one test-key-signed admission snapshot, exercised region/entity cleanup and global expiry, found no thread errors, deleted the test key, and left zero processes |

These records are process/runtime evidence, not a claim of exact Folia 1.21.1
compatibility, online-mode authentication, or production proxy forwarding. The official artifact
source and exact hashes are preserved in each machine-readable report.

## Recorded test-only raw Minecraft peer

The test-only `MinecraftProxyPlayerProbeTest` uses a bounded raw Minecraft 1.21.1
wire peer, not a standalone client or Fabric Mod. The latest passing runs reached
`AUTH_RESULT accepted` and Paper logged `admission=VERIFIED, trust=VERIFIED, risk=0`:

| Proxy | Command | Run ID and repository-relative reports | Absolute report paths | Result boundary |
| --- | --- | --- | --- | --- |
| Velocity + Paper | `./scripts/proxy-admission-player-smoke.ps1 -Proxy Velocity` | `velocity-2026-08-08T21-05-56-077744500Z`<br>`build/runtime-player-probe/runs/velocity-2026-08-08T21-05-56-077744500Z/report.json`<br>`build/runtime-player-probe/runs/velocity-2026-08-08T21-05-56-077744500Z/report.md` | `C:\Users\TT\Documents\GitHub\MCAce\build\runtime-player-probe\runs\velocity-2026-08-08T21-05-56-077744500Z\report.json`<br>`C:\Users\TT\Documents\GitHub\MCAce\build\runtime-player-probe\runs\velocity-2026-08-08T21-05-56-077744500Z\report.md` | Velocity modern forwarding, TCP/login, MCAce hello, accepted auth result, Paper admission, deleted temporary secret, and zero residual processes |
| BungeeCord + Paper | `./scripts/proxy-admission-player-smoke.ps1 -Proxy Bungee` | `bungee-2026-08-08T21-05-11-821390700Z`<br>`build/runtime-player-probe/runs/bungee-2026-08-08T21-05-11-821390700Z/report.json`<br>`build/runtime-player-probe/runs/bungee-2026-08-08T21-05-11-821390700Z/report.md` | `C:\Users\TT\Documents\GitHub\MCAce\build\runtime-player-probe\runs\bungee-2026-08-08T21-05-11-821390700Z\report.json`<br>`C:\Users\TT\Documents\GitHub\MCAce\build\runtime-player-probe\runs\bungee-2026-08-08T21-05-11-821390700Z\report.md` | Bungee IP forwarding, TCP/login, MCAce hello, accepted auth result, Paper admission, and zero residual processes |

The peer runs are loopback/offline test probes. They do not validate a real Fabric
GUI or framebuffer, online-mode authentication, or production forwarding semantics.
They also do not expand the current product beyond Fabric Mod +
Velocity/BungeeCord/Paper/Folia plugins.

## Build

Requirements: JDK 21.

```shell
./gradlew build
```

On Windows:

```powershell
.\gradlew.bat build
```

## Project layout

| Module | Responsibility |
| --- | --- |
| `mcace-protocol` | Wire contract, signing, verification, and replay defense |
| `mcace-sdk` | Stable third-party API and immutable security snapshots |
| `mcace-core` | Sessions, risk policy, evaluation, and SDK implementation |
| `mcace-storage-postgres` | Optional auditable PostgreSQL migrations, repositories, and evidence metadata hash chain |
| `mcace-cloud` | Optional authenticated ingestion, signed revocations, and portal foundations; not required for the primary path |
| `mcace-launcher` | Optional signed release verification, anti-rollback state, HTTPS download, and crash-safe installation |
| `mcace-runtime-integration` | Non-production separate-process TCP protocol test network |
| `mcace-client-common` | Loader-neutral integrity scanning primitives |
| `mcace-client-fabric` | Fabric 1.21.1 client bootstrap |
| `mcace-server-velocity` | Network admission adapter |
| `mcace-server-bungeecord` | BungeeCord handshake and signed backend-admission adapter |
| `mcace-server-paper` | Paper/Folia signed admission, status, SDK, and command adapter |

## Security and privacy

The project intentionally excludes full-disk scanning, keylogging, camera or
microphone access, browser inspection, private-file collection, hidden execution,
and kernel drivers. Please report vulnerabilities privately to the maintainers.
