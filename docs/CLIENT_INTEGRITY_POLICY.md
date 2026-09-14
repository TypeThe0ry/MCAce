# Client integrity policy / 客户端完整性策略

This document defines the MCAce v0.0.1 **policy inputs** for the requested
ModList/resource-pack workflow. It is not a claim that a client report is an
unforgeable anti-cheat verdict.

## What the client sends

At the signed authentication snapshot the Fabric client sends:

- the policy-scoped **installed-file** manifests for `mods`, `resourcepacks`, and
  `shaderpacks`;
- the actual runtime-loaded ModList from `FabricLoader.getAllMods()`, including
  at most 256 canonical Mod IDs/versions and a privacy-limited origin
  classification;
- for a loaded Mod whose origin is a direct child of `<gameDir>/mods`, the
  basename is reconciled to an installed `ModEntry` with the same Mod
  ID/version before the exact file size and SHA-256 are copied into the
  `LoadedModEntry`;
- for nested JARs, only the parent Mod ID is sent; a `PATH` origin that is not
  exactly one direct child of `<gameDir>/mods` is conservatively classified as
  `UNKNOWN`; built-in/classpath and unknown origins send no local path, absolute
  path, or classpath value;
- `selected_resource_packs` from the runtime pack repository; and
- `selected_shader_packs` when an optional shader loader exposes the active
  pack. The Fabric clients use a reflection-only Iris adapter, so the mod has
  no hard shader-loader dependency; a missing, disabled, or failed loader
  reports an empty list rather than a guessed directory entry.

The loaded ModList and the same selected-pack lists are included in every complete
`ArtifactObservationUpdate`. A runtime loaded-graph, resource-pack, or active
shader-pack change marks the ACK-driven single-flight scheduler dirty. The first
detected change before any dynamic update has been accepted may pull the first
attempt forward immediately; after the first acceptance, later changes coalesce
behind the next five-minute interval. Scan and transport failures retain dirty
state and retry with bounded exponential backoff. Installed files and loaded Mods
remain deliberately separate: a JAR present in `mods/` can be dormant, while a
nested or built-in Mod can be loaded without being a direct `mods/` file.

The client does not commit a prepared dynamic snapshot when its fragments merely
reach the transport API. It commits sequence, aggregate root, and cadence only
after verifying a server-signed `ArtifactObservationResult` whose session,
sequence, aggregate root, acceptance shape, and full-update SHA-256 all match the
exact pending update. A lost result retries that exact payload with fresh transfer
IDs, nonces, and signatures. A valid semantic rejection schedules a fresh scan;
a signed `RATE_LIMITED` result additionally supplies a bounded retry hint.

The signed policy and authentication request negotiate
`CLIENT_CAPABILITY_LOADED_MOD_GRAPH_V1`. The default Velocity and BungeeCord
policies require that capability, so an empty/legacy request cannot silently
receive verified admission under those defaults. The request advertises the
capability only when it carries the bounded non-empty graph, and every dynamic
snapshot must retain the exact authenticated capability list. The parallel
`ModEntry` list is also required to be a one-to-one metadata enrichment of the
signed `mods` scope: no installed file may be omitted and no self-consistent
extra entry may be introduced.

## Server interpretation

All client-origin observations are `CLIENT_REPORTED` and `LOW` confidence. For
Mods, the server derives `loaded=true|false`, `loaded_origin`, and
`origin_manifest_matched` metadata after validating canonical order, uniqueness,
origin-field shape, and any claimed direct-file binding. A `MOD_ID_VERSION`
selector may require `metadata { key: "loaded" value: "true" }`, which prevents a
dormant installed JAR from satisfying that identity rule. It does not promote the
claim beyond client-reported evidence. For resource and shader packs, the server
derives `selected=true|false` for file and directory content-root observations. A
signed disposition policy may match those metadata fields, an exact artifact
SHA-256, or an exact directory content root.

For a direct `mods/` origin, the copied SHA-256 represents the policy-scoped file
bytes observed on disk at scan time. It binds the loaded identity claim to that
installed manifest entry; it is not proof that those exact bytes are the code
already defined or executing inside the JVM. That stronger statement requires
an independently controlled runtime or server-side evidence source.

Recommended rollout order:

1. `OBSERVE` for a newly discovered ID or pack.
2. `NOTICE`/`WARN`/`CHALLENGE` for a reviewed exact hash or selected-pack rule.
3. `LIMIT`/`QUARANTINE`/`DENY` only after an independent server provider
   (Grim/Vulcan/another backend signal) or durable administrator authorization
   corroborates the same current session.

Velocity and BungeeCord evaluate both the initial authenticated manifest and each
accepted dynamic snapshot through the same shared signed-policy evaluator, then
submit the resulting content-free, session-bound event through the same platform
disposition executor used for that connection. Dynamic input never changes
admission. Queueing an event is not itself a punishment: the executor rechecks
the current physical session, `VERIFIED` admission, policy freshness, route
configuration, action, and evidence before acting. `NOTICE`, `WARN`, and the
content-free `CHALLENGE` message may execute from reviewed client-origin evidence;
`CLIENT_REPORTED` `LIMIT`, `QUARANTINE`, and `DENY` remain advisory unless
independent durable authority has been attached. A configured
Grim/Vulcan adapter may pass a bounded `ServerBehaviorObservation` to
`ServerBehaviorCorrelationRuntime`; only a matching current-session signal
inside the correlation window can produce a durable `SERVER_CONFIRMED`
authorization. The adapter remains responsible for authenticating its provider
event before calling this boundary.

## Exact catalog entry workflow

Never activate an identity-only catalog item as an exact detection. For a
reviewed artifact, collect the bytes from the operator-controlled fixture,
record its provenance, and calculate the hash without loading the artifact:

```powershell
$jar = (Resolve-Path 'C:\fixtures\reviewed-client.jar').Path
$hash = (Get-FileHash -LiteralPath $jar -Algorithm SHA256).Hash.ToLowerInvariant()
"sha256=$hash"
```

Copy the resulting lower-case 64-hex value into the administrator-owned
`DispositionRuleConfiguration.sha256_hex` input. The same workflow is
automated (still fail-closed) by:

```powershell
pwsh -File .\scripts\new-exact-artifact-policy.ps1 `
  -ArtifactPath C:\fixtures\reviewed-client.jar `
  -EntryId reviewed-client-2026-08 `
  -ArtifactType MOD -MatchType ExactSha256 `
  -OutputPath .\build\reviewed-client-policy.textproto
```

For a directory resource pack, use `-MatchType ContentRoot`; the script emits
the same `mcace-manifest-v1` root used by the authenticated manifest audit. It
rejects reparse points, empty directories, unsafe paths, and oversized file
sets. The generated catalog selection is explicitly `enabled: false`, so
review/provenance and false-positive notes must be completed before an
administrator enables a final action. The publisher signs the resulting policy;
the client never supplies policy authority.

## Trust state machine

`ClientTrustEvaluator` maps the wire admission snapshot plus freshness and
corroboration into one stable operator state:

| State | Meaning |
| --- | --- |
| `TRUSTED` | verified admission and a fresh observation |
| `UNTRUSTED` | missing/limited/unfinished MCAce or unknown wire trust |
| `SUSPECT` | reviewed high-risk artifact or an independent server finding |
| `BLOCKED` | current connection is explicitly blocked |
| `STALE` | verified session exists but its observation window expired |

This state is intentionally separate from the protobuf `TrustLevel`. It is the
input for future UI/metrics surfaces and does not bypass the signed policy or
the server-authority gate.

`ClientTrustEvaluator` can classify a caller-supplied observation timestamp as
`STALE`, but `ArtifactObservationUpdate` is not an ongoing freshness lease or
continuous attestation for the authenticated session. There is no periodic
server timer that revokes
`VERIFIED` admission or expires the last dynamic manifest solely because the
client stops sending updates. Client silence can therefore leave the server's
dynamic view stale. This state table is an operator/UI assessment model, not a
continuous-attestation guarantee.

## Test fixtures and real evidence

`scripts/anticheat-fixture-smoke.ps1` is metadata-only and never executes a
third-party JAR or pack. `scripts/anticheat-live-fixture-smoke.ps1` executes an
MCAce-owned controlled test entrypoint and proves only the client/server
correlation path, with a normal-client false-positive control. Both outputs must
remain labelled fixture evidence. Real authenticated server-provider events are
retained separately under `docs/evidence/` and are the only source that can
corroborate a client artifact for high-impact action.
