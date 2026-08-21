# MCAce Mod + plugin deployment migration

This guide moves an existing MCAce checkout or deployment onto the supported
Fabric Mod + Velocity/BungeeCord + Paper/Folia path without deleting preserved
legacy work. It is deliberately conservative: begin with observation, make one
reversible change at a time, and retain the signed identity and policy history.

The authoritative product boundary is [PRODUCT_SCOPE.md](PRODUCT_SCOPE.md).
This is an operator migration guide, not a claim that every optional or legacy
module is a production requirement.

## What is and is not in the trust path

The supported trust path is:

```text
Fabric Mod -> Velocity or BungeeCord -> signed admission snapshot -> Paper or Folia
```

Cloud, portal, PostgreSQL storage, and Launcher source remain in the repository
so earlier work is preserved. They are frozen extensions, not a prerequisite,
fallback, or alternate trust path for this migration. Do not introduce a
Launcher, Agent, desktop process, Cloud callback, or database availability
dependency while moving a network to this path.

For a normal migration:

- leave Paper/Folia `cloud.enabled: false`;
- leave Velocity `storage.enabled=false` in `mcace.properties`;
- do not deploy `mcace-launcher`, `mcace-cloud`, or `mcace-storage-postgres` as
  a condition for a player to become locally `VERIFIED`;
- retain legacy databases and artifacts under their existing retention/change
  process. Do not delete evidence or private keys as a migration shortcut.

The optional PostgreSQL audit implementation may be operated separately later,
but it must not decide admission, compensate for an unavailable Mod, or carry
raw evidence into the current trust path. A database outage is not a reason to
restrict an already connected player.

## Before changing a live network

1. Record the currently deployed proxy type, backend list, Fabric build ID,
   plugin versions, and the active disposition policy sequence shown by the
   relevant status command.
2. Back up each proxy data directory with access restricted to the proxy service
   account. The identity directory contains private material; do not place its
   private keys in a client, a backend, chat, a ticket, or a source repository.
3. Back up the signed disposition binary, the administrator textproto, and its
   `history/` directory as one set. The two proxy layouts are different:

   | Item | Velocity | BungeeCord |
   | --- | --- | --- |
   | Main properties | `plugins/<MCAce data>/mcace.properties` | `plugins/MCAce/mcace.properties` |
   | Identity | `plugins/<MCAce data>/identity/` | `plugins/MCAce/identity/` |
   | Signed disposition policy | `plugins/<MCAce data>/policy/signed-disposition-policy.pb` | `plugins/MCAce/disposition-policy.pb` |
   | Administrator input | `plugins/<MCAce data>/policy/disposition-policy.textproto` | `plugins/MCAce/disposition-policy.textproto` |
   | Policy history | `plugins/<MCAce data>/policy/history/` | `plugins/MCAce/history/` |

4. Start with an explicit Fabric release build ID rather than silently retaining
   `fabric-phase2-dev`. Configure the same server ID, Minecraft version, and
   build ID in the selected proxy before distributing the Mod. The exact fields
   are shown in [OPERATIONS.md](OPERATIONS.md#signed-policy-lifecycle).
5. Keep every enforcement setting in `MONITOR` while pins, policies, and known
   good client flows are being checked.

Use the current three-target strict regression path before deployment; it does
not replace live process validation:

```powershell
$env:JAVA_HOME = '<Temurin 21.0.7+6 home>'
.\gradlew.bat clean build localVerificationBundle `
  "-PmcaceModernJavaHome=<Temurin 25.0.3+9 home>" `
  --offline --dependency-verification=strict --rerun-tasks `
  --no-build-cache --no-configuration-cache --no-daemon `
  --no-parallel --max-workers=1 --console=plain
```

## Phase 1: install the supported components in monitor mode

Install exactly one proxy adapter per proxy process, the Fabric Mod plus Fabric
API on approved clients, and the Paper artifact on every Paper/Folia backend.
The supported Fabric tuple and release-ID process are in
[FABRIC_COMPATIBILITY.md](FABRIC_COMPATIBILITY.md).

The proxy creates its persistent Ed25519 identity on first start. Copy only the
public file to the places that need a pin:

```text
Proxy public file: plugins/<MCAce data>/identity/server-public-key.txt
Fabric pin file:   .minecraft/config/mcace/server-keys.properties
Paper/Folia pin:   plugins/MCAce/proxy-public-key.txt
```

Fabric uses the exact address shown in its server list as the property key:

```properties
play.example.net=BASE64_PUBLIC_KEY_FROM_PROXY
```

The backend must receive the same proxy public key, never the private key. A
backend with a missing, malformed, or non-Ed25519 pin refuses to enable MCAce.
Compare the logged SHA-256 fingerprint at the proxy and every backend before
accepting players. The old `plugins/MCAce/velocity-public-key.txt` name is read
only if the preferred `proxy-public-key.txt` does not exist. Once the preferred
pin is verified, remove the old file rather than relying on fallback behavior.

The proxy sends a signed admission snapshot after terminal authentication or a
server switch, refreshes it every five seconds, and Paper/Folia expires it after
15 seconds without a valid refresh. Unsigned or stale snapshots do not replace
the prior backend state.

### Paper and Folia safety settings

Leave each backend at its generated default:

```yaml
session-actions:
  mode: MONITOR
```

`MONITOR` records signed backend admission but takes no player-facing action. A
later `SESSION_ACTIONS` setting remains current-backend-connection-only: it may
send one LIMITED notice or disconnect only a fresh BLOCKED carrier. It never
creates a ban, device restriction, account history mutation, or proxy route.
Do not use a Paper/Folia backend as a second rule-level enforcement engine;
Velocity/Bungee own NOTICE/WARN/LIMIT/QUARANTINE/DENY policy execution.

For Folia, do not replace MCAce's scheduler path with direct asynchronous player
access. The plugin routes player-facing work through the entity scheduler and
expiry/cleanup through the global scheduler. Before deploying any supported
version, run the authoritative three-version process matrix and confirm the exact
target row. Folia 26.2 build 4 is a BETA lane and requires an explicit rollout
decision; 1.21.11 and 26.1.2 use the reviewed STABLE Folia builds.

### Phase 1 verification and rollback

Run the authoritative process gate from a controlled machine:

```powershell
.\scripts\server-version-process-matrix.ps1 -Execute
.\scripts\server-version-process-matrix.ps1 -ReportOnly
```

This loopback/offline gate covers all 12 supported version/backend/proxy cases and
binds current source, product JARs, fixed upstream assets, prepared trees, Java
runtimes, raw reports, signed admission, shadow context, and cleanup. It does not
prove online-mode identity or public-network deployment. The older 1.21.1/1.21.4
platform, Bungee, Folia, and proxy-context wrappers are historical and cannot
satisfy this migration gate.

For a target-specific server-only Fabric startup, always include the target:

```powershell
.\scripts\platform-load-smoke.ps1 -FabricTarget 1.21.11
# or: -FabricTarget 26.1.2 / 26.2
```

If a pin or plugin enablement check fails, leave enforcement at `MONITOR`, stop
the affected proxy/backend, restore the last verified public pin and matching
identity backup, then restart. Do not copy a different proxy's private identity
to make fingerprints match.

## Phase 2: migrate from one restricted target to independent limited and quarantine routes

The global proxy execution gate and the signed disposition policy are separate.
A policy can contain `ALLOW`, `NOTICE`, `WARN`, `LIMIT`, `QUARANTINE`, or
current-connection `DENY`, but high-impact actions still require the proxy's
explicit `LIMITED_ROUTE` mode. MCAce has no automatic permanent BAN action.

Start with a policy whose `rollout_stage` is `OBSERVE`, keeping the proxy gate at
`MONITOR`:

```properties
# Velocity: plugins/<MCAce data>/mcace.properties
enforcement.mode=MONITOR
disposition.limited.server=limited
disposition.quarantine.server=quarantine

# BungeeCord: plugins/MCAce/mcace.properties
disposition.enforcement.mode=MONITOR
disposition.limited.server=limited
disposition.quarantine.server=quarantine
```

Perform this configuration migration while the gate remains `MONITOR`:

1. Back up the current proxy property file and record the formerly configured
   one-target server name. Do not enable a route merely by copying a placeholder.
2. Register and health-check two different backend names in the selected proxy:
   one limited service and one independent quarantine service. A name that is
   missing, unregistered, or equal to the other target does not form a route.
3. Set both canonical `disposition.limited.server` and
   `disposition.quarantine.server` properties. For Velocity, replace the legacy
   unprefixed `limited.server` / `quarantine.server` compatibility inputs with
   these canonical keys. For BungeeCord, copy a former
   `disposition.restricted.server` value only to
   `disposition.limited.server`, then choose and register a different quarantine
   target. The old Bungee property never configures or authorizes QUARANTINE.
4. Restart the proxy in `MONITOR`, verify the normal primary handshake with a
   known-good Fabric client, and review the selected policy before enabling any
   high-impact action.

`LIMITED_ROUTE` becomes effective only when both canonical targets are distinct
and registered. Otherwise it safely behaves as `MONITOR`: normal primary
handshakes remain available and LIMIT, QUARANTINE, and DENY are all suppressed.
There is no implicit shared-target fallback.

Use the supported status commands to confirm that the signed policy is healthy
and its active sequence is the expected one:

```text
# Velocity
/mcacepolicy status

# BungeeCord
/mcace disposition
```

Then make all of the following true before changing either mode property:

1. The configured limited and quarantine backends are different, registered in
   the selected proxy, and have each been tested with known-good Fabric clients.
2. The policy has passed preview and validation and operators have reviewed the
   explicit selected action, scope, reason, and false-positive notes.
3. Initial observations, dynamic observation refreshes, evidence failures, and
   heartbeat events have been reviewed as non-punitive signals. In particular,
   a declined, unavailable, expired, or failed evidence request never produces
   a disposition event.
4. Operators understand that `DENY` disconnects only the current connection and
   that `LIMITED_ROUTE` is required for LIMIT/QUARANTINE execution.
5. The proxy has initialized `trusted-disposition-authorizations.log`, and operators
   understand that high-impact execution requires either a server-confirmed source
   authorization or `/mcacedisposition review` with permission
   `mcace.admin.disposition.review`. The review command supplies an exact artifact
   hash and ticket but no action; the active signed policy selects the action and
   the durable strict 16-column V3 journal write must succeed before execution is
   queued. The record begins with `v3` and binds session, review input, and execution
   context. At action time the proxy must still atomically validate the same physical
   lifecycle, exact current session, `VERIFIED` admission, exact context commitment,
   active policy identity/status/expiry, current winning rule, and action equality.

Only then edit the matching property to `LIMITED_ROUTE` and restart that proxy
so it reads the file. Test controlled accounts separately through the LIMIT route
and the independent QUARANTINE route. In a valid configuration, LIMIT never uses
the quarantine service and QUARANTINE never uses the limited service. Neither
action bans a player, survives a reconnect, or requests evidence automatically;
DENY only disconnects the current connection. If either route target is absent,
unregistered, or identical, the effective mode is `MONITOR`: the primary
handshake remains usable and LIMIT, QUARANTINE, and DENY are not substituted with
a kick, ban, or fallback route.

Do not promote an older trusted smoke report while migrating. Release evidence must
declare `authorization_contract=UUID_CONTEXT_COMMITMENT_V3`; V2 and contractless
reports remain invalid. The current committed chains are in
`docs/evidence/disposition-current-2026-08-21.json`; the August 13 file remains
retained history.

Rollback is a configuration rollback: set the same property back to `MONITOR`
and restart the affected proxy. That immediately prevents further high-impact
proxy execution while preserving signed observations and audit history. It does
not rewrite an already signed policy or retroactively undo an already completed
current-connection action. Keep the canonical two-target settings in the backup
unless reverting the whole proxy configuration. If an emergency requires
restoring an old Bungee one-target file, leave its execution gate at `MONITOR`:
`disposition.restricted.server` is a LIMIT-only migration source and must never
be treated as a quarantine authorization.

## Phase 3: publish and roll back disposition policy safely

Do not edit either signed `.pb` file. The editable textproto is administrator
input only. The publisher validates it, derives identity/sequence/time/
predecessor fields, signs it with the existing proxy identity, compiles it, and
atomically replaces the binary only on success.

Use this order every time:

```text
# Velocity
/mcacepolicy catalog preview
/mcacepolicy catalog validate
/mcacepolicy catalog list
/mcacepolicy catalog publish

# BungeeCord
/mcace disposition catalog preview
/mcace disposition catalog validate
/mcace disposition catalog list
/mcace disposition catalog publish
```

Preview/validate/list require `mcace.admin.check`; publishing requires
`mcace.admin.policy`. A failed validation or pre-commit history write retains
the active bytes. Successful signed versions are retained in `history/` up to
128 entries. Keep the identity, active binary, textproto, and history together
in backups.

There is intentionally no command that copies an old binary over the current
one. That would conflict with the active sequence and predecessor-chain checks.
To roll back rule *semantics*, restore the previous reviewed textproto content,
give it a new human-readable version, run preview/validate/list again, and
publish a new higher-sequence signed document. Keep proxy execution in `MONITOR`
until the new policy is understood.

Existing signed manual rules without catalog provenance remain readable; catalog
status renders such provenance as `legacy`. Do not attempt to mutate a signed
old rule to add provenance. Re-author it in the current textproto schema and
republish it as a new signed policy. `catalog_entries` themselves are inert until
an explicit enabled `catalog_selection` supplies a final action.

Run the catalog parser/provenance checks before adopting the supplied research
catalog. They never download or execute cheat binaries:

```powershell
.\scripts\test-catalog-provenance.ps1
.\scripts\verify-catalog-provenance.ps1
# Optional explicit network review only:
.\scripts\verify-catalog-provenance.ps1 -Live -TimeoutSeconds 10
```

See [DISPOSITION_POLICY.md](DISPOSITION_POLICY.md) and
[DETECTION_CATALOG.md](DETECTION_CATALOG.md) for rule/action ceilings and the
evidence ladder. Client-reported identity alone is never a permanent punishment
reason.

## Phase 4: evidence transport, v1 compatibility, and retention

The current transport is Begin/Chunk/Commit. Images must not use the old
single-field `EvidenceResponse.content` path. The Fabric Mod supports one
`GAME_RENDER_FRAME` only after a visible, signed, per-request `Allow once`.
`GAME_WINDOW` and `DESKTOP` remain unsupported zero-content results; they do not
call an operating-system capture API.

Old evidence requests that omit the retention fields remain compatible and mean:

```text
raw_content_retained=false
retention_seconds=0
retention_policy_id=""
retention_purpose=""
```

This is a default-discard request, not an implied permission to retain content.
For retention, the signed request must disclose a positive duration no longer
than 24 hours plus a non-empty policy ID and purpose. The Fabric screen must
show the same disclosure, and decline/close/expiry/unavailable/upload failure
has no risk, admission, route, or punishment effect.

Each proxy first creates a disabled storage file at
`plugins/<MCAce data>/evidence-storage.properties` (for Bungee, `<MCAce data>`
is `plugins/MCAce`). Keep it disabled unless there is an approved consent and
retention contract:

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

To opt in, set `enabled=true`,
`client-consent-contract-confirmed=true`, a positive retention value at most
86,400 seconds, policy ID, purpose, and a dedicated key path. The key is a
separate 32-byte AES-256 key; never reuse a proxy Ed25519 identity or policy
signing key. Restrict the evidence root, key, audit log, and backup media to the
proxy service account and approved reviewers.

New retained objects use the authenticated v2 AES-256-GCM envelope. Review reads
accept only v2. Legacy v1 records remain accessible only through the existing
caller-supplied-metadata read path during migration; there is no automatic raw
content conversion. Preserve any v1 data under its prior retention process,
switch new collection to the disabled-by-default/v2 path, and do not claim that
legacy objects have gained v2 authentication. Wrong key, expiry, tampering, or
malformed metadata fails closed.

Use only content-free administrative controls:

```text
/mcaceevidence storage status
/mcaceevidence storage delete <evidence-id> <reason>
```

The commands require `mcace.admin.evidence`; they do not print raw bytes or
keys. The encrypted store enforces the configured object/file/total quotas and
sweeps at most 32 expired objects each minute. Confirm a deletion with status
and the content-free evidence audit, then retain the deletion audit under the
same approved retention policy. An optional local reviewer, when separately
enabled, is loopback-only and console-issued; it is not a public raw-image
portal.

The manual real Fabric UI evidence gate is still required for a release that
depends on that flow:

```powershell
.\scripts\platform-load-smoke.ps1 -FabricTarget 1.21.11 -WithFabricEvidence
.\scripts\platform-load-smoke.ps1 -FabricTarget 26.1.2 -WithFabricEvidence
.\scripts\platform-load-smoke.ps1 -FabricTarget 26.2 -WithFabricEvidence
```

Each target requires a graphical local Fabric run and two distinct human clicks: one explicit-file decision and one frame decision. Across three targets that is six clicks. The script does not
automate consent, mouse input, window capture, desktop capture, or account login.

## Phase 5: enable federation only after both operators pin each other

Federation is optional and starts disabled. It is a short-lived client-carried
observation, not a Cloud service, proxy-to-proxy channel, alternate local trust
path, or enforcement signal. No source/target socket, HTTP callback, broker, or
instant remote revocation exists.

On first start each proxy creates `federation.properties` in its own MCAce data
directory and `federation-audit.log` beside it. Keep the audit log restricted:
it is content-free lifecycle metadata, not a place for grants, keys, nonces,
challenges, manifests, evidence, risk data, IP addresses, or screenshots.

Each side needs an independent offline configuration decision. For a source
network `network-east` permitted to issue toward `network-west`:

```properties
schema.version=1
enabled=true
local.network-id=network-east
assertion.ttl.seconds=120
peer.ids=network-west
peer.network-west.public-key-x509-base64=BASE64_X509_ED25519_PUBLIC_KEY
peer.network-west.key-id-sha256=SHA256_OF_THE_SAME_X509_KEY
peer.network-west.capabilities=ISSUE_TO
```

On `network-west`, independently pin `network-east` with the same three peer
fields but use `ACCEPT_FROM`. The peer key ID must match the SHA-256 of the
declared X.509 key. `ISSUE_TO` and `ACCEPT_FROM` are directional least-privilege
capabilities; a one-sided pin, a shared display name, discovery, wildcard, or
trust-on-first-use is insufficient. A configuration may contain at most 64
peers, rejects unknown/duplicate properties, and accepts an assertion TTL only
within the protocol's five-minute maximum.

Restart each edited proxy to read the complete configuration. Invalid federation
configuration or audit initialization disables federation only; it must not
disable the normal local handshake/admission bridge. Check the safe command
output with `mcace.admin.federation`:

```text
/mcacefederation status
/mcacefederation peers
/mcacefederation issue <player> <target-network-id>
```

Before issuing, require `configured=true enabled=true audit=HEALTHY` and
`audit_failures=0`. `enabled=false configured=true audit=FAILED` means the
process has latched an audit fault: stop issuing, preserve the restricted audit
file for review, fix quota/path/storage health, and restart the proxy. The fault
does not self-clear on configuration reload. Successful issue/grant/observation
states are returned only after the audit worker confirms the durable file
append; an accepted queue item is never treated as durable evidence.

`issue` is an explicit source-operator action for a player that is currently
locally `VERIFIED`. Fabric displays exact source/target information, short key
fingerprints, expiry, and the observation-only disclosure with `Allow once` and
`Decline`. Only a one-time visible allow can produce the signed consent. The
client carries the grant and short-lived source session key in memory only; it
may survive a completed source disconnect until expiry, but is cleared on use,
expiry, discard, or client shutdown.

At the target, the player must independently complete local `VERIFIED`
authentication with that same short-lived client key before the target accepts a
session/challenge-bound proof of possession. Fabric reserves that exact prepared
presentation and shows a separate target-import prompt containing the exact
source/target identities, fingerprints, disclosure, and expiry. The source
decision is not reused: only a second visible target `Allow once` sends the
presentation. Decline, close, connection change, or expiry sends nothing and
cannot alter local admission. An accepted remote statement is
only `FEDERATION_SOURCE_LOCALLY_VERIFIED` / remote corroboration. It cannot
change local trust, risk, disposition, route, message, disconnect, ban, evidence
handling, or Paper/Folia admission. Remove `enabled=true` or the relevant pin
and restart the local proxy to stop new use; already signed grants cannot be
instantly revoked and instead expire within their signed lifetime.

The durable record `docs/evidence/federation-durable-audit-2026-08-13.json` shows
that the historical schema-2 matrix passed all four proxy pairs (4/4) and then passed
`-ReportOnly`. It binds older proxy artifacts/source and is not current release evidence:

- Velocity to Velocity
- Velocity to Bungee
- Bungee to Velocity
- Bungee to Bungee

The separate target-restart gate passed on its first current-source execution and
then passed `-ReportOnly`, recording `residual_reacceptance=true`,
`durable_replay_protection=false`, and `fabric_gui_coverage=false`. The former P2
cold-listener readiness race was fixed by waiting, after plugin initialization,
for the exact selected-port loopback listener marker; the pure marker unit test
also passed. The durable record copies no raw reports or identifiers.

Re-run all four only as an explicit opt-in process gate:

```powershell
.\scripts\federation-proxy-matrix-smoke.ps1 -Pair All
```

The matrix proves source-local authentication, an explicit issue, in-memory grant
carry after source disconnect, independent target authentication, observation,
same-assertion replay rejection, unchanged local trust/risk/admission, signed
Paper admission, content-free audit, healthy durable-audit state at source and
target, and owned-process cleanup. It uses a
test-only raw peer, not a rendered Fabric consent UI. Real Fabric federation
consent and the complete privacy scan remain release gates; do not treat the
matrix as proof of those rows.

The current `scripts/fabric-federation-gui-handoff-smoke.ps1` is a fail-closed V2
wrapper for all three supported Fabric targets. Its PowerShell 7 and Windows
PowerShell 5 static contract tests pass, and both source-export and target-import
screens are implemented. A migration still needs a real human execution: approve
source export, disconnect and use Direct Connection for the exact target, approve
target import, then keep that connection alive through signed expiry while the
wrapper verifies target observation, Paper admission, unchanged local state,
cleanup, and privacy. No static or raw-peer record substitutes for that run.

## Completion checklist and rollback order

Before calling a migration complete, record:

1. matching Fabric client pin and every Paper/Folia backend pin fingerprint;
2. proxy policy status and configuration mode (`MONITOR` or `LIMITED_ROUTE`);
3. signed policy sequence/version and review of every enabled high-impact rule;
4. evidence storage status, retention disclosure, dedicated key ownership, and
   deletion audit, or confirmation that storage remains disabled;
5. federation status/peers only if explicitly enabled; and
6. the relevant process-gate report paths plus known boundaries.

For an incident, reverse in this order: set the proxy execution mode to
`MONITOR`; disable federation locally; disable new raw-evidence retention; then
restart only the affected proxy/backend after preserving content-free logs and
the existing signed artifacts. This sequence stops newly enabled effects without
deleting forensic records, pins, policy history, or private keys. Follow the
organization's separate incident/retention process for any legacy Cloud or
PostgreSQL data.

For current safety boundaries, release gates, and exact protocol semantics, see
[OPERATIONS.md](OPERATIONS.md), [DETECTION_AND_EVIDENCE.md](DETECTION_AND_EVIDENCE.md),
[FEDERATION.md](FEDERATION.md), and [PLATFORM_TESTING.md](PLATFORM_TESTING.md).
