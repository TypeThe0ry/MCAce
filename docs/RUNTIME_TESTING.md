# Runtime protocol testing

## Purpose and boundary

`mcace-runtime-integration` contains two different classes of tests:

- the default, pure loopback protocol suite, which starts a bounded server JVM and
  malformed/known-good client JVMs; and
- opt-in real Velocity/BungeeCord plus Paper/Folia process tests, orchestrated by
  the authoritative three-version wrapper.

The raw Minecraft peer is test tooling. It is not a standalone client product and
cannot supply real Fabric GUI consent.

The August 20 strict offline Windows A/D builds each completed 118/118 tasks with
JDK `21.0.7+6`, isolated modern JDK `25.0.3+9`, and Gradle `9.6.1`. Root results
were 147 suites / 681 tests / 0 failures / 0 errors / 28 skipped; modern results
were 24 / 74 / 0 / 0 / 0; combined results were 171 / 755 / 0 / 0 / 28. The
exact-eight local bundle was byte-identical across A and D. Durable sanitized
evidence is
[`evidence/local-build-2026-08-20.json`](evidence/local-build-2026-08-20.json);
build output remains mutable. The current bundle remains LOCAL verification
with `source_commit=LOCAL_UNSPECIFIED`.

Current Linux run `cb6dc44ddad744b5a20dc2986c0a6d70` passed strict
offline network-none verification with exact JDK 21.0.7+6 and JDK 25.0.3+9. It
covered 118 root actionable tasks plus 15/15 modern tasks and 171 suites / 755
tests / 0 failures / 0 errors / 33 environment-conditioned skips. The 735-file
source manifest `b74c22ff187a1fcfe4d8e1d6da5a202bde67d72061bcb3c2f205532d3857f8c3`
was unchanged, all exact-eight entries were stream-byte-identical to Windows A/D,
and cleanup reached zero containers and zero run-scoped Java processes at
0/30/60 seconds. The external witness SHA-256 is
`de6d82fedace1c7b961ba9879b6e924df1bc8a1d085b851134194bac91d44b48`.
The old exact-six and pre-fix exact-eight runs remain historical.

## Run the default protocol suite

Requirements: root JDK 21. No Minecraft installation or external network is
required.

```powershell
.\gradlew.bat :mcace-runtime-integration:test --rerun-tasks --no-daemon
```

The JUnit parent starts one loopback TCP server JVM and thirteen independent
client JVMs. Four clients complete normally; nine exercise replay, forged
signature, oversize/truncation, malformed Protobuf, ordering, wrong UUID, unpinned
root, or incompatible-build paths. Each connection receives its own production
`ServerHandshakeCoordinator`.

Targeted process gates can overwrite the module's in-place JUnit XML. Use the
sanitized durable local-build record, not an arbitrary later
`build/test-results` directory, as whole-build evidence.

## Run the real three-version proxy/backend matrix

```powershell
.\scripts\server-version-process-matrix.ps1 -Execute
.\scripts\server-version-process-matrix.ps1 -ReportOnly
```

The matrix executes exactly 12 cases:

| Dimension | Values |
| --- | --- |
| Minecraft | `1.21.11`, `26.1.2`, `26.2` |
| Backends | Paper, Folia |
| Proxies | Velocity, BungeeCord |
| Java | JDK 21 for 1.21.11; JDK 25 for 26.1.2 and 26.2 servers |
| Lanes | 10 STABLE; 2 BETA for Folia 26.2 |

Each case reaches accepted proxy authentication, accepts the proxy-signed backend
admission, emits the content-free backend-context shadow audit, and leaves zero
run-owned processes. The wrapper binds source, current product JARs, fixed
upstream JARs, protocol profile, JDK/Gradle identities, prepared server tree, and
raw-report digest. Private/delegated keys and forwarding secrets must be absent
after cleanup.

The current Helio run `2026-08-24T20-23-23-6783068Z` passed all 12 cases and then
passed `-ReportOnly`: Paper 6/6, Folia 6/6, Velocity 6/6, and BungeeCord 6/6. Folia
26.2 build 6 remains explicitly BETA. Current durable evidence is
[`evidence/server-version-process-matrix-2026-08-25-395a769.json`](evidence/server-version-process-matrix-2026-08-25-395a769.json),
bound to code commit `395a769…`.
The standard-backend observer requires admission and context while the same peer
socket remains live; it does not count post-close log output.
The context path is shadow-only and cannot invoke admission, routing,
disconnect, punishment, evidence, or disposition.

The former `proxy-admission-player-smoke.ps1` and
`proxy-folia-context-smoke.ps1` aggregates for Paper 1.21.1 and Folia 1.21.4 are
historical. They are not current three-version release evidence.

## Opt-in real disposition advisory-origin guard matrix

Run this gate only when real proxy processes are intended. It is skipped by a
normal Gradle test invocation unless `mcace.runtime.disposition.enabled=true`
is set. The wrapper runs Velocity before Bungee and never overlaps real proxy or
Paper processes:

```powershell
.\scripts\disposition-proxy-matrix-smoke.ps1 -Proxy Both -FabricTarget 1.21.11
.\scripts\disposition-proxy-matrix-smoke.ps1 -Proxy Both -FabricTarget 26.1.2
.\scripts\disposition-proxy-matrix-smoke.ps1 -Proxy Both -FabricTarget 26.2
```

Each Velocity and BungeeCord case uses one real proxy and three independently
named Paper backends (`lobby`, `limited`, and `quarantine`). The administrator
publisher signs and activates the isolated `runtime-synthetic-v1` exact-SHA
 policy, and the raw peer supplies the matching manifest as `CLIENT_REPORTED`
 evidence. The current eight-case definition runs `MONITOR_LIMIT`,
 `ENFORCE_LIMIT`, `ENFORCE_QUARANTINE`, and `ENFORCE_DENY` on both proxies. The
 latter names mean that
`LIMITED_ROUTE` was configured and the policy requested the action; they do not
mean that a client report was allowed to execute it.

A case passes only when the exact runtime policy is active, authentication is
accepted, the audit records a positive advisory-origin enforcement block, the
connection remains on `lobby`, neither restricted backend accepts the player,
no disposition route lifecycle occurs, the current connection remains live, and
owned process/run-material cleanup completes. Bungee can establish exact policy
activation from the fixed audit version when console acknowledgement and ACTIVE
markers are split or unavailable across logger sinks; it never credits an
unrelated observation count.

The current three-target Execute plus ReportOnly runs passed 24/24 cases (8/8 per
target). The sanitized committed chains are recorded at:

- `docs/evidence/disposition-current-2026-08-21.json`

Use `-ReportOnly` to revalidate and aggregate the latest sanitized case reports
without starting processes. Per-case reports keep `matrix_completed=false`;
the validated `-Proxy Both` aggregate includes both DENY cases with no route and no
connection close and sets `matrix_completed=true`.
Every case deletes its forwarding secret, generated identities, client cache,
signed policy/history, run-local observer plugin copy, and redirected process
output. Reports retain no hash, rule identifier, policy bytes, key, session,
UUID, raw frame, path, log content, or disconnect reason.

## Opt-in real trusted disposition process matrix

Run the trusted action gate separately from the advisory-origin matrix:

```powershell
.\scripts\trusted-disposition-proxy-matrix-smoke.ps1 -Proxy Both -FabricTarget 1.21.11
.\scripts\trusted-disposition-proxy-matrix-smoke.ps1 -Proxy Both -FabricTarget 26.1.2
.\scripts\trusted-disposition-proxy-matrix-smoke.ps1 -Proxy Both -FabricTarget 26.2
```

It is disabled during ordinary builds and enabled only with
`mcace.runtime.trusted-disposition.enabled=true`. Each real Velocity and Bungee
case first reaches a clean `VERIFIED` lobby admission. An authorized operator then
submits `/mcacedisposition review <player> <ticket>
<mod|resource-pack|shader-pack|config> <identifier> <version> <sha256>`. The
command has no action parameter: the active signed exact-hash policy selects LIMIT,
QUARANTINE, or DENY. Before the event can be queued, the runtime must durably append
the strict 16-column V3 TSV record (first column `v3`) containing the authorization
identity plus session, review-input, and execution-context commitments. An unavailable,
malformed, or exhausted journal fails closed. Immediately before action, the proxy
revalidates the exact current session and `VERIFIED` admission in the same physical
lifecycle, then checks the exact context commitment, active policy identity/status/expiry,
current winning rule, and `rule.action == event.action` in one policy-atomic boundary.

The six serial cases are required to prove successful distinct LIMIT and QUARANTINE routes on both
proxies, plus current-connection-only DENY. Each DENY case waits for the first
connection to disappear, reconnects the same offline identity under an independent
session with a clean manifest, and requires a fresh verified `lobby` admission. No
case creates a permanent ban or lets a client report independently authorize an
action. The current three-target V3 aggregate passed all 18 cases (6/6 per target)
on 1.21.11, 26.1.2, and 26.2. Execute plus ReportOnly passed, and the sanitized
committed chains are recorded at:

- `docs/evidence/disposition-current-2026-08-21.json`

It declares `authorization_contract=UUID_CONTEXT_COMMITMENT_V3`, confirms journal
persistence before execution in every case, and keeps `fabric_gui_coverage=false`.
Use `-ReportOnly` to validate and aggregate six sanitized V3 reports without starting
processes; it must reject V2 or contractless reports. The passing aggregate does not
claim a real-process `SERVER_CONFIRMED` artifact producer.

## Opt-in real federation proxy matrix

The federation process matrix is disabled during ordinary Gradle builds. Run all
four Velocity/Bungee source-target pairs sequentially with:

```powershell
.\scripts\federation-proxy-matrix-smoke.ps1 -Pair All
```

The wrapper validates each sanitized raw report and emits an aggregate. Use
`-ReportOnly` to revalidate reports without starting processes. The retained
`docs/evidence/federation-durable-audit-2026-08-13.json` records a historical schema-2
aggregate that passed 4/4 plus `-ReportOnly` and recorded process-memory-only client carry, no source-target
broker, source disconnect before target authentication, same-process replay
rejection, unchanged target trust/risk/Paper admission, and zero residual
processes. It binds older proxy artifacts/source; current-source execution and
`-ReportOnly` are pending. Every case also requires `source_audit_healthy=true` and
`target_audit_healthy=true`, obtained from each real proxy's content-free
`/mcacefederation status` output after the flow. The raw peer auto-produces test
consent only because the gate was explicitly enabled;
`fabric_gui_coverage=false` remains truthful. Report-only mode rejects old
schema-1 reports.

The separate `scripts/fabric-federation-gui-handoff-smoke.ps1` contract is now
V2 and accepts exactly `1.21.11`, `26.1.2`, or `26.2`. It launches the selected
final Fabric artifact and requires six exact runtime markers: requested,
rendered, and allowed-once for source export, then the same three markers for
target import. Its static contract tests pass under PowerShell 7 and Windows
PowerShell 5. This is implementation evidence only: a PASS still requires a
human source decision, source disconnect and direct target join, a distinct
human target decision, target-local `VERIFIED` plus Paper admission, a live
target session through signed expiry, observation cleanup, privacy checks, and
zero owned processes.

Run the target-restart residual separately:

```powershell
.\scripts\federation-target-restart-residual-smoke.ps1
```

The former P2 cold-listener readiness race is fixed: `startProxy` now waits, after
the MCAce plugin initialization marker, for the exact selected-port platform marker
`Listening on /127.0.0.1:<port>`. The pure readiness-marker unit test passed, and
the current-source schema-2 restart gate passed on its first execution and then
passed `-ReportOnly`. It proved old
target-session bindings fail after restart and honestly recorded that
a retained unexpired grant can create a fresh observation because target replay
state is process-local: `residual_reacceptance=true` and
`durable_replay_protection=false`. It is observation-only, retains
`fabric_gui_coverage=false`, requires healthy source/target durable-audit state,
and leaves zero remaining owned processes.

## Legacy hostile-admission wrapper

`paper-folia-hostile-admission-smoke.ps1` is retained for older defensive fixture
reproduction. Its own Minecraft version allowlist still ends at 1.21.4, so it is
not a current 1.21.11/26.x release gate and its old Paper/Folia command examples
must not be used as three-version evidence.

The current server release gate is `server-version-process-matrix.ps1`. Any future
hostile-admission gate for the supported versions must consume the reviewed
`build/runtime-assets` manifest, use the same exact Java split and protocol
profiles, bind current product JARs, and publish separately sanitized evidence.

## Scenario matrix

| Scenario | Expected result | Risk | Protocol violation |
| --- | --- | ---: | --- |
| Four independent known-good clients | `VERIFIED / VERIFIED` | 0 | No |
| Replayed `CLIENT_HELLO` | `LIMITED / UNKNOWN` | 100 | Yes |
| Forged client signature | `LIMITED / UNKNOWN` | 80 | Yes |
| Oversized frame declaration | `LIMITED / UNKNOWN` | 80 | Yes |
| Truncated frame body | `LIMITED / UNKNOWN` | 80 | Yes |
| Malformed Protobuf | `LIMITED / UNKNOWN` | 80 | Yes |
| `AUTH_REQUEST` before `CLIENT_HELLO` | `LIMITED / UNKNOWN` | 80 | Yes |
| Asserted UUID differs from connection UUID | `LIMITED / UNKNOWN` | 50 | Yes |
| Server root is not pinned | `LIMITED / UNKNOWN` | 20 | No response/timeout |
| Client build is incompatible with policy | `LIMITED / UNKNOWN` | 20 | No response/timeout |

Malformed input is controlled and loopback-only. It verifies fail-closed
admission without creating a ban or other irreversible action.

## Evidence semantics

The server emits a trace for each complete frame with scenario label,
direction, sequence, byte length, and SHA-256. Transport rejection classes and
final admission snapshots are also emitted. Raw frames and private keys are not
logged. Ed25519 keys, nonces, session IDs, the ephemeral port, and resulting
frame hashes intentionally vary between runs; the scenario set and asserted
outcomes are deterministic.

The JUnit parent forcibly terminates a child that exceeds its bound, and its
`finally` cleanup terminates the server if an assertion or child fails. A clean
run must report one test, zero failures, zero errors, and zero skipped tests, with
no remaining `RuntimeNetworkMain` process.
