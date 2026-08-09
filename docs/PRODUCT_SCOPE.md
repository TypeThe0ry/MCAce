# MCAce product scope

## Authoritative delivery shape

MCAce is delivered primarily as one client Mod plus server plugins:

```text
Fabric client Mod (priority)
        |
        | signed mcace:handshake / heartbeat / scoped integrity manifest
        v
Velocity or BungeeCord proxy plugin
        |
        | signed mcace:admission snapshot
        v
Paper or Folia backend plugin
        |
        +-- MCAce SDK / Grim / optional Vulcan / operator review
```

The client Mod proves only the observations it can collect inside the Minecraft
process and explicitly consented game instance. Proxy and backend plugins remain
the authoritative policy, replay, correlation, and admission boundary.

## Required platforms

- Client priority: Fabric for Minecraft 1.21.1 and subsequent supported releases.
- Proxy plugins: Velocity and BungeeCord.
- Backend plugin: one Paper-compatible implementation with explicit Folia-safe
  scheduling and runtime validation.
- Shared modules: protocol, core session/risk engine, SDK, and local persistence.

NeoForge, Forge, a standalone client, Launcher, Agent, and mandatory Cloud
services are outside the current delivery roadmap. They must not become a
prerequisite or an alternate trust path for the Fabric Mod/plugin product.

## Preserved legacy components

Previously implemented Cloud, Web portal, Launcher research, and PostgreSQL
storage are retained to avoid deleting existing work, but are frozen outside the
current product roadmap. Runtime harnesses and platform smoke tests remain active
test tooling for the Mod/plugin path. The current product must not require a
standalone Launcher, separate desktop client, Windows Agent, or Cloud deployment.
The presence of legacy source in the repository is not a delivery claim.

No existing implementation is removed merely because it is optional. Shared
protocol/security primitives should be merged into the Mod/plugin path when they
improve it without creating a new mandatory process.

## Trust semantics

- `UNKNOWN`: no successfully authenticated Mod session.
- `VERIFIED`: current Fabric Mod completed the signed, replay-resistant handshake
  and policy-scoped integrity collection.
- `TRUSTED` and `SECURE`: reserved values. No component in the current product
  may upgrade a player to these levels; Fabric evidence remains client-reported
  and cannot be a sole punishment signal.

Missing Mod state may route a player to a limited server when configured, but
does not automatically ban, punish, or create a confirmed-cheat label.

## Privacy and enforcement invariants

- Only Minecraft instance `mods`, `resourcepacks`, `shaderpacks`, and explicitly
  consented configuration files are in scope.
- No full-disk scanning, hidden process, keylogging, camera, microphone, browser
  data, private files, or kernel driver.
- Client observations retain provenance and require server corroboration for
  high-impact decisions.
- Every restriction policy needs monitor mode, rollback, operator review, and an
  appeal path.

## Evidence boundary

- Evidence capture is Fabric-only and currently supports one `GAME_RENDER_FRAME`
  after a visible, signed, per-request `Allow once` consent. It does not add a
  reusable permission, client-side screenshot file, or desktop/window API.
- A legacy request that omits retention fields means `raw_content_retained=false`,
  `retention_seconds=0`, and empty policy/purpose. A retained request must be
  signed and bound to the session, player, request ID, scope, and request TTL; its
  disclosed retention is positive and no longer than 24 hours, with a non-empty
  policy ID and purpose. The client rejects contradictory, expired, or tampered
  requests before display or authorization.
- `GAME_WINDOW` and `DESKTOP` are permanently unsupported in the current scope:
  they do not capture or retain content and return zero-content
  `UNSUPPORTED`/`DECLINED` outcomes. Closing, declining, expiry, and unavailable
  capture carry no punishment or admission penalty.
- A screenshot is client-reported evidence, never a standalone cheat conclusion.
  The current repository has bounded encrypted storage controls, but no raw-image
  reviewer retrieval UI. Real Minecraft UI/proxy evidence-flow smoke remains a
  release gate.
