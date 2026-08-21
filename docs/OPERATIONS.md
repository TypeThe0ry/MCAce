# Mod + server-plugin operator guide

For the staged migration order, legacy-component freeze boundary, policy rollback,
evidence retention transition, and optional federation rollout, see
[MIGRATION.md](MIGRATION.md).

Historical durable federation process evidence is retained at
`docs/evidence/federation-durable-audit-2026-08-13.json`. The four-pair matrix
passed 4/4 plus `-ReportOnly`. That retained run binds older proxy artifacts/source;
current-source matrix and restart execution are pending. The restart gate passed on its first historical
execution and then passed `-ReportOnly`. The former P2 cold-listener readiness race
was fixed by waiting for the exact selected-port loopback listener marker after
proxy-plugin initialization, with a passing pure marker unit test. The current
restart result records
`residual_reacceptance=true`, `durable_replay_protection=false`, and
`fabric_gui_coverage=false`.
The separate V2 graphical handoff wrapper and source-export/target-import screens
are now implemented for all three targets, with PowerShell 7 and Windows
PowerShell 5 static contract tests passing. No human-executed V2 PASS exists yet.

## Components

- Put either the Velocity or BungeeCord artifact in the proxy `plugins` directory.
- Put exactly one target-matched Fabric artifact and its exact Fabric API in the
  client's `mods` directory: `1.21.11` / `0.141.6+1.21.11` on Java 21,
  `26.1.2` / `0.155.2+26.1.2` on Java 25, or `26.2` /
  `0.157.0+26.2` on Java 25. All are built and tested with Loader `0.19.3`.
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

The generated development policy is a bounded exact allowlist. For development,
choose one supported Minecraft/build-ID pair. A three-target release uses the
target-specific immutable commit-bound IDs documented in
`FABRIC_COMPATIBILITY.md`:

```text
# Velocity plugins/<MCAce data>/mcace.properties
policy.server-id=network-east
policy.minecraft-versions=1.21.11,26.1.2,26.2
policy.client-build-ids=fabric-1.21.11-<commit>,fabric-26.1.2-<commit>,fabric-26.2-<commit>

# Bungee plugins/MCAce/mcace.properties
server.id=network-east
minecraft.version=1.21.11
client.build-id=fabric-1.21.11-<commit>
```

Fabric embeds the Gradle build ID plus the resolved Mod and Minecraft versions in
`fabric.mod.json`, then reads those processed values into the signed hello. Do not
reuse the development ID for distinct release bytes. Velocity accepts bounded,
comma-separated version/build lists for staged migration. Bungee accepts one exact
Minecraft version and one exact client build ID per configuration; use the matching
`26.1.2` or `26.2` tuple instead when that proxy serves a modern target, rather than
placing comma-separated values in those fields. A configuration change immediately
publishes a higher-sequence policy; changing `server-id` also rotates the delegated
signer so the trust statement cannot retain the old network ID.

## Reproducible supply chain

Use Temurin `21.0.7+6` for the root project and Temurin `25.0.3+9` for the
isolated `fabric-modern/` build. Both require Gradle `9.6.1`. Auto-download is
disabled for the modern Java toolchain; pass the reviewed JDK 25 home explicitly.

The root verification metadata has 47 exact Loom-local trust entries. The modern
metadata has two exact named-Minecraft trust entries. Every rule fixes the exact
coordinate and file; there is no broad group trust. POMs, mappings, upstream
modules, Fabric dependencies, and native `protoc` artifacts remain SHA-256
verified. The old 52-rule figure belongs to the superseded 1.21.1 build and must
not be used as the current trust inventory.

Run dirty-safe local verification with:

```powershell
$env:JAVA_HOME = '<Temurin 21.0.7+6 home>'
.\gradlew.bat clean build localVerificationBundle `
  "-PmcaceModernJavaHome=<Temurin 25.0.3+9 home>" `
  --offline --dependency-verification=strict --rerun-tasks `
  --no-build-cache --no-configuration-cache --no-daemon `
  --no-parallel --max-workers=1 --console=plain
```

The August 20 A/D runs each completed 118/118 tasks. Root results were 147
suites / 681 tests / 0 failures / 0 errors / 28 skipped; modern results were
24 / 74 / 0 / 0 / 0; combined results were 171 / 755 / 0 / 0 / 28. Both runs
produced byte-identical exact-eight bundles. Durable sanitized evidence is
[`evidence/local-build-2026-08-20.json`](evidence/local-build-2026-08-20.json);
files below `build/` remain mutable diagnostics.

`build/local-verification-bundle/` contains exactly:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `mcace-client-fabric-1.21.11.jar` | 3,385,438 | `e6b02463c4e65bc81a825626b98559d94ab5eed642fc84e6552a22bf7dc1d323` |
| `mcace-client-fabric-26.1.2.jar` | 3,489,094 | `26de3b15fa56aff684f04076df4464fe409d9f0185147aec05efd0c296a72d35` |
| `mcace-client-fabric-26.2.jar` | 3,489,092 | `4f6ee9077b3a9986f253c49db3e867c4ed480871c7e6023509d6b19d1ef4bc73` |
| `mcace-server-velocity.jar` | 5,016,132 | `0f5afa9cc04aa3e3d21b7142fb2156ee4059d1f2f1f36508b33fbdd59c4323be` |
| `mcace-server-bungeecord.jar` | 3,562,568 | `fc7ac9ac84a673bd08f15e5a68bbdaadd30af157ac154a20a14dcefbe6e4152a` |
| `mcace-server-paper.jar` | 5,924,608 | `d133a093ff684490dcb3ae81e2751498c5fc9eeb9fe0c6f0bbce802f5dd23e7b` |
| `release-manifest.properties` | 1,797 | `7e73e7cc99ea1f6328060697107caf308b0b3ecccead7c0c61621ed661cfc8f7` |
| `SHA256SUMS` | 565 | `b0227412fe38ad781edf998a217f2338f16caa6589763e7447cb1f956a3ef6b1` |

The local manifest is `MCACE_LOCAL_VERIFICATION_BUNDLE_V1`, has
`bundle_profile=LOCAL_VERIFICATION`, `release_identity=false`, and
`source_commit=LOCAL_UNSPECIFIED`. Never label it as a release candidate.

After review and commit, create the release candidate with the same strict flags,
`releaseBundle`, `-PmcaceModernJavaHome=<reviewed JDK 25 home>`, and
`-PmcaceSourceCommit=<exact lowercase 40-hex HEAD>`. `releaseBundle` requires the
tracked and untracked worktree to be clean, requires the supplied commit to equal
`git rev-parse HEAD`, and re-reads all exact-eight entries. Exact-commit protected
CI must pass before publication.

Current Linux run `cb6dc44ddad744b5a20dc2986c0a6d70` passed with the
repository mounted read-only, network mode `none`, strict offline dependency
verification, root JDK 21.0.7+6, and modern JDK 25.0.3+9. It covered 118 root
actionable tasks (105 executed, 13 up-to-date), 15/15 modern tasks, and 171
suites / 755 tests / 0 failures / 0 errors / 33 environment-conditioned skips.
The 735-file, 6,375,429-byte source manifest
`b74c22ff187a1fcfe4d8e1d6da5a202bde67d72061bcb3c2f205532d3857f8c3`
was identical before and after the run. Exact-eight canonical manifest
`289a59e56c6605e2f5ba7af160a9c94da506978e3c5db6e5c4102b578ce2ada3`
matched Windows A/D by name, size, SHA-256, and direct stream bytes. Cleanup left
zero containers and zero run-scoped Java processes at 0/30/60 seconds, and
the disposable cache was removed. Linux has five additional recorded skips
because the isolated container has no external PostgreSQL service; they are not
failures. The external witness SHA-256 is
`de6d82fedace1c7b961ba9879b6e924df1bc8a1d085b851134194bac91d44b48`;
it is not repository evidence. The old exact-six and pre-fix exact-eight runs
are historical.

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

## Administrator-reviewed high-impact authorization

Use the review command only after the player has a current `VERIFIED` admission and
the expected signed policy sequence is active:

```text
/mcacedisposition review <player> <ticket> <mod|resource-pack|shader-pack|config> <identifier> <version> <sha256>
```

The source requires `mcace.admin.disposition.review`. Prefer the proxy console or a
narrowly authorized operator role. `<ticket>`, identifier, and version are bounded
single tokens; never put secrets or private file paths in them. The SHA-256 must be
exactly 64 hexadecimal characters. There is intentionally no action parameter: the
active signed policy selects the action, rule, and policy sequence. Check the
returned authorization UUID and
`session-bound=true execution-context-bound=true execution-queued=true` marker.
Any other status means no action was authorized.

Before queuing the event, MCAce force-appends a bounded audit record to:

- Velocity: `plugins/mcace/trusted-disposition-authorizations.log`
- BungeeCord: `plugins/MCAce/trusted-disposition-authorizations.log`

The current journal is strict 16-column TSV: column one is `v3`, and the record
contains authorization/player IDs, time, trusted origin, operator and ticket,
selected action/rule, policy identity, plus session, review-input, and
execution-context commitments. It contains no artifact hash, identifier, version,
manifest, path, or raw evidence. Before action, MCAce revalidates the same physical
lifecycle, exact current session, `VERIFIED` admission, and exact context commitment,
then atomically verifies the active policy identity/status/expiry, current winning
rule, and that the rule action equals the event action. An unsafe path, initialization
failure, write failure, or exhausted 8 MiB quota fails closed. Protect and retain the
journal as operator audit metadata. Roll back new high-impact execution by returning
the proxy to `MONITOR` and restarting it; this does not erase prior audit records.
DENY remains current-connection-only and never creates a permanent ban.

Release evidence for this path must report
`authorization_contract=UUID_CONTEXT_COMMITMENT_V3`. The current three-target V3
matrix passed 18/18 administrator-reviewed cases (6/6 per target), with Execute
and ReportOnly both passing. The sanitized committed chains are recorded in
`docs/evidence/disposition-current-2026-08-21.json`; the August 13 aggregate remains
retained history.
V2 and contractless reports remain invalid for release evidence.

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

### Three-version proxy/backend matrix

The authoritative release wrapper is:

```powershell
.\scripts\server-version-process-matrix.ps1 -Execute
.\scripts\server-version-process-matrix.ps1 -ReportOnly
```

It executes the complete 3 versions × Paper/Folia × Velocity/Bungee matrix. The
August 20 run `2026-08-20T12-01-09-3951618Z` passed 12/12 and then passed `-ReportOnly`: Paper
6/6, Folia 6/6, Velocity 6/6, Bungee 6/6, with 10 STABLE cases and two Folia
26.2 BETA cases. Current durable evidence is
[`evidence/server-version-process-matrix-2026-08-20.json`](evidence/server-version-process-matrix-2026-08-20.json).

`-ReportOnly` starts no process. It validates only the latest complete committed
report/binding/commit triplet against current inputs. Any source, wrapper, asset,
prepared-tree, Java, Gradle, product-JAR, or raw-report drift fails closed.

The old 1.21.1/1.21.4 `bungee-paper-load-smoke.ps1`,
`folia-process-smoke.ps1`, `proxy-admission-player-smoke.ps1`, and
`proxy-folia-context-smoke.ps1` results are historical. Their old Paper 1.21.1-133,
BungeeCord 2028, and Folia 1.21.4-6 ALPHA assets cannot satisfy the current
1.21.11/26.1.2/26.2 release gate.

### Fabric platform and consent gate

`-FabricTarget` is mandatory:

```powershell
# Server-only startup; passed for all three targets.
.\scripts\platform-load-smoke.ps1 -FabricTarget 1.21.11
.\scripts\platform-load-smoke.ps1 -FabricTarget 26.1.2
.\scripts\platform-load-smoke.ps1 -FabricTarget 26.2

# Visible full evidence gate; run once for every target.
.\scripts\platform-load-smoke.ps1 -FabricTarget 1.21.11 -WithFabricEvidence
.\scripts\platform-load-smoke.ps1 -FabricTarget 26.1.2 -WithFabricEvidence
.\scripts\platform-load-smoke.ps1 -FabricTarget 26.2 -WithFabricEvidence
```

All target version manifests, asset indexes, and asset objects are already in the
validated cache. The remaining gate is human input: one visible explicit-file
approval and one separate visible frame approval per target, six clicks total.
The wrapper does not automate those decisions or control an existing Minecraft
process.

A passing pair uses report schema 6 and binding
`MCACE_FABRIC_GUI_EVIDENCE_BINDING_V4`. It must load only the exact final
artifact, bind the entrypoint CodeSource SHA-256, bind current server/JDK/Gradle/
asset/prepared-tree inputs, bind `velocity_policy_minecraft_versions` and
`velocity_policy_client_build_ids`, prove both consent chains, and leave zero
exact run-token Java processes. 1.21.11 uses the final remapped JAR; both 26.x
targets use final named JARs.

The GUI pair is LOCAL process evidence, not automatic release identity. Revalidate
it with `-ReportOnly`, the same `-FabricTarget`, and independently reviewed
expected hashes. Current output must not act as its own expected value.

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

## Backend context shadow audit

After accepting the latest signed admission snapshot, Paper/Folia publishes its Bukkit-derived
world key and game mode on `mcace:context`. The payload contains no backend claim. Velocity/Bungee
derive backend identity from the event-supplied server connection that carries the target player,
then require the exact physical login/session, player UUID, admission transport sequence, monotonic
report sequence, and bounded age. This deliberately avoids depending on an eventually consistent
current-server pointer during an early backend plugin message. Client-originated frames on this
channel are consumed without parsing and cannot create context.

Accepted context produces only the aggregate log marker `backend context shadow audit`. It cannot
change admission, route, disconnect, ban, or invoke a disposition executor. A transient
`REJECTED_BINDING` may appear when a newer signed admission sequence supersedes an older backend
report; it is fail-closed diagnostic output, and the release gate still requires a later accepted
aggregate audit marker. Operators must investigate version, clock, and sequence continuity without
automatic player action.

Current real-process evidence covers Paper and Folia 1.21.11, 26.1.2, and 26.2 through both Velocity and BungeeCord. The authoritative 12-case aggregate is linked above; Folia 26.2 remains a BETA lane. This does not establish online-mode identity, GUI consent, public-network behavior, or production-configuration compatibility.

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
