# Mod + server-plugin operator guide

For the staged migration order, legacy-component freeze boundary, policy rollback,
evidence retention transition, and optional federation rollout, see
[MIGRATION.md](MIGRATION.md).

## Components

- Put either the Velocity or BungeeCord artifact in the proxy `plugins` directory.
- Put the Fabric artifact and Fabric API 0.116.15+1.21.1 in the client's `mods`
  directory. The current client targets Minecraft 1.21.1 and Java 21.
- Put the Paper artifact in every Paper/Folia backend's `plugins` directory and
  install the selected proxy public-key pin described below. The backend exposes
  the SDK/status command and consumes short-lived signed admission snapshots.

## Establish the server identity pin

1. Start the selected proxy once with MCAce installed.
2. Copy the contents of
   `plugins/mcace/identity/server-public-key.txt`. Never copy or distribute
   `server-private-key.pk8`.
3. On each approved client, create
   `.minecraft/config/mcace/server-keys.properties`.
4. Add the address exactly as shown in the Minecraft server list:

```properties
play.example.net=BASE64_PUBLIC_KEY_FROM_PROXY
```

An optional `default=...` entry applies to addresses without an exact match. An
absent or invalid pin fails closed: the client logs the issue and does not answer
the challenge.

## Establish the Paper backend pin

Copy the selected proxy's public file—not its private key—to every backend:

```text
Proxy:       plugins/<MCAce data>/identity/server-public-key.txt
Paper/Folia: plugins/MCAce/proxy-public-key.txt
```

The legacy `plugins/MCAce/velocity-public-key.txt` filename is still accepted only
when `proxy-public-key.txt` is absent, so existing deployments are not broken. If
both files exist, Paper/Folia always uses `proxy-public-key.txt`; a malformed new
pin therefore fails closed instead of silently falling back to the old key. Operators
should verify the replacement key and then remove the legacy file. Paper/Folia
refuses to enable MCAce if the selected pin is missing, malformed, or is not an
Ed25519 public key. On success it logs the SHA-256 fingerprint. Compare that value
with the proxy during provisioning. Changing the proxy root requires updating
both Fabric address pins and every backend pin.

The proxy publishes a root-signed snapshot after a terminal handshake or server
switch, then refreshes it every five seconds. The backend expires the local snapshot
after 15 seconds without a valid refresh and removes it immediately on player
quit. Unsigned or stale messages leave the prior state unchanged.

Velocity and BungeeCord retain `MONITOR` and opt-in `LIMITED_ROUTE` modes. Both
proxies now have a session-bound, bounded, idempotent disposition executor. The
safe default is `MONITOR`: it may emit sanitized NOTICE/WARN/CHALLENGE hints, but
does not execute high-impact actions. `LIMITED_ROUTE` is required for LIMIT or
QUARANTINE and requires two different, registered proxy targets:
`disposition.limited.server` and `disposition.quarantine.server`. LIMIT routes
only to the limited target; QUARANTINE routes only to the separate quarantine
target. If either target is absent, unregistered, or names the other target, the
effective mode safely becomes `MONITOR`: the primary handshake remains usable and
LIMIT, QUARANTINE, and DENY do not execute. With a valid route configuration,
DENY still disconnects the current connection only; it never bans the player,
crosses a reconnect boundary, triggers automatic evidence collection, or creates
a later punishment.

## Request one game-frame evidence item

Operators need `mcace.admin.evidence`. On either supported proxy, use:

```text
/mcaceevidence request <player> <frame|window|desktop> [case-id]
```

`frame` sends a signed request with a maximum two-minute lifetime. The Fabric
Mod displays a visible `Allow once` / `Decline` screen containing the case and
expiry and, when configured, the exact signed retention duration, policy ID, and
purpose. Old requests explicitly display that raw content is not retained. Only
an explicit one-time approval captures one Minecraft-rendered frame. Closing or
ignoring the prompt declines or expires it. `window` and `desktop` currently
return a zero-content unavailable/declined outcome; they do not invoke an
operating-system capture API.

The command reports only request identifiers and status. It never prints image
content. Decline, unavailable, expired, failed, and invalid outcomes do not add
risk, change admission, route a player, or create a ban. The default content
store verifies the upload and discards raw bytes. A screenshot is never a
standalone cheat conclusion. Real Minecraft UI/proxy evidence-flow smoke is
still a release gate, and the repository does not provide a raw-image reviewer
retrieval UI.

## Optional raw-evidence storage

The proxy creates `plugins/<MCAce data>/evidence-storage.properties` on first
start. Its safe default is:

```properties
enabled=false
client-consent-contract-confirmed=false
root=plugins/<MCAce data>/evidence
key=plugins/<MCAce data>/evidence-storage.key
retention-seconds=0
retention-policy-id=
retention-purpose=
max-bytes=16777216
max-files=256
max-total-bytes=268435456
```

Raw storage remains discard-only until an operator deliberately sets
`enabled=true`, `client-consent-contract-confirmed=true`, a positive retention
duration no greater than 86,400 seconds, a non-empty policy ID/purpose, and a
dedicated 32-byte AES-256 key path. Do not reuse the Ed25519 server identity or
policy signing key. The store enforces 16 MiB per object, 256 files, and 256 MiB
total by default; it never silently expands these quotas. A bounded scheduler
deletes at most 32 expired objects per minute.

With `mcace.admin.evidence`, both supported proxies expose only bounded
administrative metadata:

```text
/mcaceevidence storage status
/mcaceevidence storage delete <evidence-id> <reason>
```

Deletion records the operator identity, reason, timestamp, evidence ID, and
whether an object was deleted. Status and command output never expose raw image
bytes or keys. Configure Windows NTFS ACLs so only the proxy service account and
approved operators can access the dedicated evidence directory and key; ordinary
`Path` operations and privileged directory replacement remain residual host risks.
The current implementation has no raw-image reviewer retrieval UI.

## Signed policy lifecycle

Velocity stores the current document at
`plugins/mcace/policy/signed-policy.pb`. It is signed by the persistent server
identity's delegated policy key, valid for 24 hours, and renewed within its last
hour with a higher sequence. The root-signed trust statement is embedded in the
document. Clients cache the highest accepted policy under
`.minecraft/config/mcace/policies/` and reject rollback or conflicting content at
the same policy or trust sequence.

The delegated key is stored under
`plugins/mcace/policy/delegated-key/`. It is authorized for 14 days and rotates
automatically within its final two days. Rotation advances the root trust
sequence and records the previous key ID in the signed revocation list. Back up
the entire `identity` and `policy` directories together; never distribute either
private key.

For suspected delegated-key exposure, an operator with the
`mcace.admin.policy` permission can run:

```text
/mcacepolicy rotate
```

The command immediately creates a new delegated key and policy, advances both
sequences, and places the former key ID in the root-signed revocation list. Active
handshakes retain at most their configured short timeout; new handshakes receive
the replacement trust state.

The generated development policy permits only Minecraft 1.21.1 Fabric build
`fabric-phase2-dev`. Before publishing a release, build the Mod with an immutable
release identifier and configure both proxies to accept that exact identifier:

```text
.\gradlew.bat :mcace-client-fabric:build -PmcaceClientBuildId=fabric-release-2026-08-09.1

# Velocity plugins/<MCAce data>/mcace.properties
policy.server-id=network-east
policy.minecraft-versions=1.21.1
policy.client-build-ids=fabric-release-2026-08-09.1

# Bungee plugins/MCAce/mcace.properties
server.id=network-east
minecraft.version=1.21.1
client.build-id=fabric-release-2026-08-09.1
```

Fabric embeds the Gradle build ID plus the resolved Mod and Minecraft versions in
`fabric.mod.json`, then reads those processed values into the signed hello. Do not
reuse the development ID for distinct release bytes. Velocity accepts bounded,
comma-separated version/build lists for staged migration. A configuration change
immediately publishes a higher-sequence policy; changing `server-id` also rotates
the delegated signer so the trust statement cannot retain the old network ID.

The policy requires `mods`, optionally inventories
`resourcepacks`/`shaderpacks`, and may request `options.txt`, which is also in the
client's local consent set. Editing a signed binary policy by hand invalidates its
signature. Use the bounded textproto publisher described below for disposition
rules; the handshake policy remains separately signed and managed.

## Detection/disposition policy source

Detection rules use a separate signed document from the handshake policy:

```text
Velocity: plugins/<MCAce data>/policy/signed-disposition-policy.pb
Bungee:   plugins/<MCAce data>/disposition-policy.pb
```

If the file is absent, the proxy atomically creates a root-signed, zero-rule
`OBSERVE` bootstrap document valid for 24 hours. The bootstrap cannot restrict,
route, disconnect, or punish a player. Existing files are read through a 1 MiB
hard limit and must be a regular non-symlink file with a valid signature and
structure. MCAce never overwrites, repairs, or re-signs a malformed, oversized,
expired, or wrong-key existing document.

Policy health is refreshed without an admission side effect. Inspect it with:

```text
Velocity: /mcacepolicy status
Bungee:   /mcace disposition
```

Velocity status/rotation/publishing require `mcace.admin.policy`; its catalog
preview/validate/list operations use `mcace.admin.check`. Bungee status and
catalog preview/validate/list use `mcace.admin.check`, while publishing uses
`mcace.admin.policy`. Output contains only bounded health, counts, action/category
summaries, warnings, and active sequence. `catalog list` additionally shows at
most eight sanitized catalog source records: entry ID, query-free HTTPS source URI,
full source revision, repository manifest path, retrieval time, and legacy marker.
It never shows a private key, URL query/token, artifact hash, local absolute path,
or raw manifest/rule content.

The fixed operator input is created without overwriting an existing file:

```text
Velocity: plugins/<MCAce data>/policy/disposition-policy.textproto
Bungee:   plugins/<MCAce data>/disposition-policy.textproto
```

After editing that file, use the same safe workflow on either proxy:

```text
Velocity: /mcacepolicy catalog preview
          /mcacepolicy catalog validate
          /mcacepolicy catalog list
          /mcacepolicy catalog publish
Bungee:   /mcace disposition catalog preview
          /mcace disposition catalog validate
          /mcace disposition catalog list
          /mcace disposition catalog publish
```

`catalog_entries` are inert until an administrator adds an explicit enabled
`catalog_selection` with a final action. The supplied starter catalog's Wurst,
LiquidBounce, and Meteor Client manifest identities are all `LOW`/`OBSERVE` and
disabled; it contains no binary or hash evidence. Each uses a fixed HTTPS GitHub
manifest URI, 40-hex source revision, manifest path, and retrieval time as
identity-only provenance. Non-exact identity matches cannot exceed WARN.
CHALLENGE/LIMIT/QUARANTINE require an exact SHA-256 or bounded directory content root;
connection-only DENY requires an independently reviewed exact SHA-256. Publication
is atomic and chained; validation failure retains the last known-good signed bytes.
Never edit the signed `.pb` file. See [`DISPOSITION_POLICY.md`](DISPOSITION_POLICY.md),
[`DETECTION_CATALOG.md`](DETECTION_CATALOG.md), and the safe
[`../examples/disposition-catalog.textproto`](../examples/disposition-catalog.textproto)
starter. A missing or invalid replacement leaves the evaluator explicitly
observation-only.

## Large manifest transport and audit evaluation

MCAce limits every client/proxy plugin-message frame to 30 KiB. Authentication
requests that fit remain on `mcace:handshake`; larger requests are automatically
sent on `mcace:payload` as signed 16 KiB fragments. Velocity and BungeeCord must
allow and register both channels. The complete authentication request remains
limited to 1 MiB and 64 chunks, with one in-flight transfer per player session.

After successful authentication, the proxy derives observations from every entry
in the signed scope manifests and evaluates them asynchronously. A winning signed
disposition can be handed to the proxy executor, but only a current authenticated
session with `VERIFIED` admission may execute it. Logs contain the player UUID,
observation/action counts, consistency-issue count, policy status, and truncation
state; they do not contain raw manifests or local paths. Queue saturation is logged
as a dropped audit and does not change trust, admission, or routing. Duplicate and
late executor deliveries are bounded and idempotent.

Disposition execution fails closed for a missing, malformed, expired, or otherwise
invalid policy, no winning rule, a late/stale session, or a non-`VERIFIED` session.
An evidence request that is declined, unsupported, expired, refused, or fails to
transfer never creates a disposition event. `CHALLENGE` is only a sanitized hint;
it does not claim that a screenshot was requested or sent.

## Admission and disposition-route mode

Use the two canonical route keys on both supported proxies. They are deliberately
not pre-populated with usable targets: choose two different server names that are
already registered in that proxy before setting `LIMITED_ROUTE`.

Velocity creates `plugins/mcace/mcace.properties`; BungeeCord uses
`plugins/MCAce/mcace.properties`:

```properties
# Velocity
enforcement.mode=MONITOR
disposition.limited.server=limited
disposition.quarantine.server=quarantine
handshake.timeout.seconds=5

# BungeeCord
disposition.enforcement.mode=MONITOR
disposition.limited.server=limited
disposition.quarantine.server=quarantine
```

- `MONITOR` only records `VERIFYING`, `VERIFIED`, or `LIMITED` state.
- `LIMITED_ROUTE` sends LIMIT only to `disposition.limited.server` and QUARANTINE
  only to `disposition.quarantine.server`; the two must differ and both be
  registered. An invalid pair makes the effective mode `MONITOR`, while retaining
  the normal primary handshake; it suppresses LIMIT, QUARANTINE, and DENY.
- `MONITOR` is the default and does not execute LIMIT, QUARANTINE, or DENY. Neither
  mode creates a ban, reconnect-spanning penalty, or automatic evidence request.
  Do not enable routing until both distinct targets are registered and known-good
  clients have been replay-tested.
- Velocity accepts legacy `limited.server` and `quarantine.server` only as
  compatibility inputs. Migrate them to the canonical `disposition.*` keys rather
  than relying on those legacy names. BungeeCord's former
  `disposition.restricted.server` can migrate only to
  `disposition.limited.server`; it never configures or authorizes QUARANTINE.
- The timeout is constrained to 2–30 seconds.

## Optional missing-heartbeat session control

Both proxy property files default to disabled:

```properties
heartbeat.missing.enabled=false
heartbeat.missing.consecutive-polls=3
heartbeat.missing.action=NOTICE
```

When enabled, `consecutive-polls` must be 2–300 and only uninterrupted
`MISSING` samples count; `STALE` is not actionable. `NOTICE` sends a fixed
session warning. `LIMITED_ROUTE` additionally requires the proxy's existing
global `LIMITED_ROUTE` mode and the valid two-target route configuration; a
missing, duplicate, or unregistered target safely leaves the effective mode at
`MONITOR`. When it is effective, this temporary control uses only the limited
target. It does not change admission/risk/trust, ban or disconnect, request
evidence, or force a return to a prior backend server. A valid heartbeat clears
the temporary control. Use content-free proxy logs to review apply/recovery events
before enabling routing.

## Optional PostgreSQL audit storage

Storage is disabled by default. Enable it only after provisioning a dedicated
database role and password environment variable. See
[`DATABASE.md`](DATABASE.md) for TLS configuration, migration commands, least
privilege grants, evidence-chain semantics, and the real PostgreSQL verification
command.

Database loss after startup does not penalize connected players: session/event
writes use a bounded asynchronous queue and failures are logged as operator
incidents. If storage is enabled and startup migration or connectivity fails,
Velocity initialization fails closed so operators do not unknowingly run an
expected-audit deployment without persistence. This PostgreSQL path is optional
and stores audit/metadata foundations; it is not the current raw-image reviewer
retrieval UI or a prerequisite for the primary Mod/plugin path.

## Runtime protocol verification

Run the separate-process loopback gate before publishing protocol, policy, or
handshake changes:

```powershell
.\gradlew.bat :mcace-runtime-integration:test --rerun-tasks --no-daemon
```

The gate does not require Minecraft or an open external port. See
[`RUNTIME_TESTING.md`](RUNTIME_TESTING.md) for its scenario matrix, evidence
output, and platform-test boundary.

## Real platform load verification

These are opt-in, process-level gates. Every server binds only to an ephemeral
loopback listener, uses an independent `build/platform-smoke*/runs/<run-id>`
root, and records cleanup. The final recorded runs all report `passed` and
cleanup zero run-owned processes.

Velocity + Paper:

```powershell
.\scripts\platform-load-smoke.ps1
```

Report: `build/platform-smoke/runs/20260808T171235524Z/report.json`.
The run used official PaperMC Fill artifacts Velocity `3.5.1-615`
(`https://fill-data.papermc.io/v1/objects/b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3/velocity-3.5.1-615.jar`,
SHA-256 `b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3`)
and Paper `1.21.1-133`
(`https://fill-data.papermc.io/v1/objects/39bd8c00b9e18de91dcabd3cc3dcfa5328685a53b7187a2f63280c22e2d287b9/paper-1.21.1-133.jar`,
SHA-256 `39bd8c00b9e18de91dcabd3cc3dcfa5328685a53b7187a2f63280c22e2d287b9`).
The report contains the source object URLs, plugin hashes, loopback binds,
missing-pin fail-closed result, and cleanup result. The default command does
not start Fabric and does not inspect or control an existing user process.

BungeeCord + Paper:

```powershell
.\scripts\bungee-paper-load-smoke.ps1
```

Report: `build/platform-smoke-bungee/runs/20260808T173618257Z/report.json`.
The fixed artifacts were BungeeCord Jenkins build `2028`
(`https://hub.spigotmc.org/jenkins/job/BungeeCord/2028/artifact/bootstrap/target/BungeeCord.jar`,
SHA-256 `45a5aa27b9f2446c320447148913aee5673ec23ddf30c81d6dafa9dd910a91eb`)
and Paper `1.21.1-133`
(`https://fill-data.papermc.io/v1/objects/39bd8c00b9e18de91dcabd3cc3dcfa5328685a53b7187a2f63280c22e2d287b9/paper-1.21.1-133.jar`,
SHA-256 `39bd8c00b9e18de91dcabd3cc3dcfa5328685a53b7187a2f63280c22e2d287b9`).
The report records the Spigot Jenkins/PaperMC Fill source URLs, loopback-only
endpoints, preferred and legacy pin acceptance, missing-pin fail closed, and
cleanup. No real player was connected, so live handshake and live Bungee
backend forwarding remain untested; the backend gate was fixture-based.

Folia + Paper plugin:

```powershell
.\scripts\folia-process-smoke.ps1
```

Report: `build/platform-smoke-folia/runs/20260808T173923329Z/report.json`.
The official Fill API had no exact Folia `1.21.1` build, so the smoke tested
official Folia `1.21.4-6` `ALPHA`
(`https://fill-data.papermc.io/v1/objects/dcf2333211c1468c8eddc482bc8549600818cc661a709124a79c752f8fa2ac3a/folia-1.21.4-6.jar`,
SHA-256 `dcf2333211c1468c8eddc482bc8549600818cc661a709124a79c752f8fa2ac3a`); the
report preserves both the requested version and the fallback source URL. The
run proved valid-pin loading, missing-pin fail closed, the real global scheduler,
and a safe console status read with no positive thread-error markers. It did not
create a player, so entity scheduler execution is covered by unit tests only.

The smoke also found and the Paper scheduler now fixes a Folia compatibility
issue where reflective invocation on Folia's non-public scheduled-task
implementation failed with `IllegalAccessException`. Cancellation now uses the
public `ScheduledTask` contract and shutdown is idempotent when the scheduler is
already halted.

The full Fabric player-flow gate is explicit:

```powershell
.\scripts\platform-load-smoke.ps1 -WithFabricClient
```

It is opt-in and must not control an existing user Minecraft process. It is a
separate gate from the default platform smoke and still does not constitute a
real evidence-consent, `GAME_RENDER_FRAME` upload, retention, or reviewer-flow
smoke. These platform reports prove process-load boundaries; they do not claim
complete player-flow coverage.

The separate test-only raw Minecraft 1.21.1 peer is run with:

```powershell
.\gradlew.bat :mcace-runtime-integration:test --tests com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest
```

The latest passing reports are `velocity-2026-08-08T18-46-57-039870Z` and
`bungee-2026-08-08T18-46-12-984562400Z`. Their repository-relative paths are:

- `build/runtime-player-probe/runs/velocity-2026-08-08T18-46-57-039870Z/report.json`
- `build/runtime-player-probe/runs/velocity-2026-08-08T18-46-57-039870Z/report.md`
- `build/runtime-player-probe/runs/bungee-2026-08-08T18-46-12-984562400Z/report.json`
- `build/runtime-player-probe/runs/bungee-2026-08-08T18-46-12-984562400Z/report.md`

The corresponding absolute paths under this checkout are:

- `C:\Users\TT\Documents\GitHub\MCAce\build\runtime-player-probe\runs\velocity-2026-08-08T18-46-57-039870Z\report.json`
- `C:\Users\TT\Documents\GitHub\MCAce\build\runtime-player-probe\runs\velocity-2026-08-08T18-46-57-039870Z\report.md`
- `C:\Users\TT\Documents\GitHub\MCAce\build\runtime-player-probe\runs\bungee-2026-08-08T18-46-12-984562400Z\report.json`
- `C:\Users\TT\Documents\GitHub\MCAce\build\runtime-player-probe\runs\bungee-2026-08-08T18-46-12-984562400Z\report.md`

Both reports record accepted `AUTH_RESULT`, and their Paper logs record
`admission=VERIFIED, trust=VERIFIED, risk=0`; both report
`remaining_run_processes=[]`. This is a test-only raw peer, not an independent
client product. It does not cover real Fabric GUI/framebuffer capture, online-mode,
or production forwarding. The Fabric evidence client remains client-reported;
common/Fabric tests cover ACK sequence, resize/generation cancellation, and buffer
clearing (49 tests), but real GUI/framebuffer consent and upload smoke remains open.

## Root-key backup and recovery

## Local evidence review (opt-in)

Each proxy creates `evidence-review.properties` in its MCAce data directory with
safe defaults: `enabled=false`, `bind=127.0.0.1`, `port=0`, a 60-second token TTL,
and 16 active tokens. A non-loopback bind, unknown or repeated key, malformed or
oversized configuration, TTL outside 10–300 seconds, or token limit outside 1–128
fails closed without affecting proxy admission.

Review starts only when retained storage explicitly provides an `EvidenceReviewReader`.
Only the proxy console may issue `/mcaceevidence review <evidence-uuid> <reason>`.
The resulting single-use localhost URL and expiry are returned to that console only;
they must never be sent in player chat or copied to a public web service. Shutdown
closes the local listener and invalidates outstanding links.

Back up both identity files together with restricted access. Restoring only one
file intentionally prevents startup. Delegated policy-key rotation does not
change client pins. Changing the root identity still requires securely
redistributing the new public pin to every client; there is intentionally no
automatic trust transfer away from the key the player pinned.

## Expected events

| Event | Trust/admission result | Operator action |
| --- | --- | --- |
| Valid pinned handshake | `VERIFIED` | Correlate with behavior systems |
| No client/no pin/timeout | `UNKNOWN` / `LIMITED` | Check installation and clock |
| Replay or malformed frame | `UNKNOWN` / `LIMITED`, investigation risk | Review logs; do not infer a ban alone |
| Expired/rolled-back/incompatible policy | Client does not scan or answer | Check clocks, persisted policy, build ID, and pin |
| Revoked/unauthorized policy signer | Client does not scan or answer | Inspect policy/trust sequences and delegated-key directory; do not delete the root identity |
| Missing limited server | Player remains connected and an error is logged | Fix Velocity server registration |
## Backend-local session actions

Paper and Folia consume only an admission snapshot that has already passed the
pinned proxy signature, replay, freshness, and carrier-UUID checks. Backend-local
actions are explicitly disabled by default:

```yaml
session-actions:
  mode: MONITOR
```

`MONITOR` records the accepted state and performs no player-facing action. To
enable reversible actions for the current backend connection only, set
`session-actions.mode: SESSION_ACTIONS`. In that mode, a fresh `LIMITED` snapshot
sends at most one bounded notice for that accepted transition; a fresh `BLOCKED`
snapshot may disconnect only the current carrier connection. Neither mode creates
a ban, device block, account history mutation, proxy route decision, or permanent
punishment. A later `VERIFIED` snapshot restores the local state; snapshot expiry,
player quit, and plugin disable clear local action state.

On Folia, player-facing actions run through the entity scheduler. Expiry and
cleanup run through the global scheduler, so no player object is accessed from a
global task.
