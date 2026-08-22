# Client integrity policy / 客户端完整性策略

This document defines the MCAce v0.0.1 **policy inputs** for the requested
ModList/resource-pack workflow. It is not a claim that a client report is an
unforgeable anti-cheat verdict.

## What the client sends

At the signed authentication snapshot the Fabric client sends:

- the policy-scoped `mods`, `resourcepacks`, and `shaderpacks` manifests;
- the locally derived ModList entries reconciled to the exact `mods` file
  name/size/SHA-256 tuple;
- `selected_resource_packs` from the runtime pack repository; and
- `selected_shader_packs` when a loader exposes that repository.

The same selected-pack lists are included in every bounded
`ArtifactObservationUpdate`. A runtime resource-pack change calls
`ArtifactObservationSendSchedule.triggerNow`, so it is reported immediately;
the normal bounded refresh remains periodic and single-flight.

## Server interpretation

All client-origin observations are `CLIENT_REPORTED` and `LOW` confidence.
The server derives a `selected=true|false` metadata field for every resource
or shader-pack entry and for directory content-root observations. A signed
disposition policy may match that field, an exact artifact SHA-256, or an exact
directory content root.

Recommended rollout order:

1. `OBSERVE` for a newly discovered ID or pack.
2. `NOTICE`/`WARN`/`CHALLENGE` for a reviewed exact hash or selected-pack rule.
3. `LIMIT`/`QUARANTINE`/`DENY` only after an independent server provider
   (Grim/Vulcan/another backend signal) or durable administrator authorization
   corroborates the same current session.

The proxy queues both the initial manifest and dynamic observation through the
same signed policy evaluator. Queueing an event is not itself a punishment;
the current session, policy freshness, route configuration, and evidence are
rechecked on the scheduler thread before an action is attempted. A configured
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

## Test fixtures and real evidence

`scripts/anticheat-fixture-smoke.ps1` is metadata-only and never executes a
third-party JAR or pack. Its output must remain labelled fixture evidence. Real
server provider events are retained separately under `docs/evidence/` and are
the only source that can corroborate a client artifact for high-impact action.
