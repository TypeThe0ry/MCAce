# Behavior anti-cheat integrations

MCAce's Paper adapters consume anti-cheat flags as **observations**, not verdicts.
They never cancel an anti-cheat event, change admission, kick, ban, or invoke a
punishment command. Cloud remains the authority for policy weights and returns
`enforcement_action=NONE` for every risk ingestion request.

## Signal flow and false-positive controls

1. Both adapters normalize only player UUID, provider/version, check identity,
   violation level, and server timestamp. Grim additionally preserves its typed
   experimental flag. The reviewed Vulcan event contract has no experimental
   accessor, so its normalized value is conservatively fixed to `false`. Raw
   packet data, coordinates, IP addresses, and verbose debug text are not collected.
2. Flags are grouped by player, provider, and stable check in a bounded sliding
   window. Nothing is uploaded until `minimum-flags` is reached.
3. A per-key cooldown suppresses repeated uploads, queues and in-memory keys are
   bounded, and network work never runs on the Paper main thread.
4. A provider is independent only after it reaches its own threshold. One
   provider emits `corroborated=false`; two independently thresholded providers
   within the window emit `corroborated=true`.
5. Cloud assigns the policy weight and stores provenance as
   `SERVER_CONFIRMED`. This means the server confirmed receipt of the alert—not
   that cheating was proven. Human review remains required.

Grim uses its official typed `FlagEvent` channel and leaves the threaded
cancelled state unchanged. MCAce compiles against GrimAPI 1.6.0.9 with a
`compileOnly` dependency, so Grim is not bundled into the Paper artifact.

Vulcan is proprietary and has no publicly verifiable stable API contract. The
adapter therefore loads its known flag event reflectively, at `MONITOR`
priority, and ignores cancelled events. A missing or incompatible API disables
only the Vulcan adapter and logs one bounded diagnostic; MCAce admission and the
other adapter continue running. Validate this bridge against the licensed
Vulcan build before enabling it in production.

## Provision a Paper Cloud identity

Create a dedicated Ed25519 identity for each Paper instance; do not copy the
Velocity private identity between machines. With OpenSSL:

```powershell
openssl genpkey -algorithm ED25519 -outform DER -out cloud-server-private-key.pk8
openssl pkey -inform DER -in cloud-server-private-key.pk8 -pubout -outform DER |
  openssl base64 -A
```

Add the printed public key to Cloud's `servers.registry` with only the required
scope:

```text
paper-1|BASE64_X509_ED25519_PUBLIC_KEY|RISK_WRITE
```

Place the private `.pk8` in `plugins/MCAce/`, restrict it to the service account,
and configure `plugins/MCAce/config.yml`:

```yaml
behavior:
  enabled: true
  minimum-flags: 3
  window-seconds: 10
  cooldown-seconds: 30
  maximum-tracked-keys: 10000
  grim:
    enabled: true
  vulcan:
    enabled: true

cloud:
  enabled: true
  endpoint: "https://mcace.example.net"
  server-id: "paper-1"
  private-key-path: "cloud-server-private-key.pk8"
  queue-capacity: 1024
  request-timeout-ms: 5000
```

HTTPS is mandatory except for an explicitly loopback Cloud endpoint. Failed
authentication, a full queue, timeouts, or Cloud unavailability drop only the
affected observation and produce an operator diagnostic; they never penalize a
player. Normal plugin shutdown drains the queue for up to five seconds.

## Compatibility gate

Run the module tests before deployment:

```powershell
.\gradlew.bat :mcace-cloud-client:test :mcace-server-paper:test --rerun-tasks --no-daemon
```

The tests cover signed challenge/token/risk HTTP delivery, loopback-only plain
HTTP, threshold and cooldown behavior, bounded state, independent-provider
corroboration, and a synthetic fixture for the narrow reflective Vulcan event
contract.

Before attempting a licensed runtime, run the local artifact preflight with an
operator-obtained JAR:

```powershell
$vulcanJar = 'C:\licensed-plugins\Vulcan.jar'
$vulcanSha256 = (Get-FileHash -LiteralPath $vulcanJar -Algorithm SHA256).Hash.ToLowerInvariant()

.\scripts\vulcan-licensed-api-compatibility-smoke.ps1 `
  -VulcanJar $vulcanJar `
  -ArtifactSha256 $vulcanSha256

# Revalidate the newest bound report without reopening the proprietary JAR:
.\scripts\vulcan-licensed-api-compatibility-smoke.ps1 `
  -ReportOnly `
  -ArtifactSha256 $vulcanSha256
```

The gate rejects UNC paths, mapped network drives, and any artifact or parent path
implemented by a reparse point. It keeps the direct JAR open with read-only sharing
for the entire preflight and compares size and SHA-256 from that same handle before
and after inspection. The script requires the configured Gradle distribution to
already have a local wrapper-validation marker, then invokes that installed
`gradle.bat` directly with `--offline`; it never runs the wrapper launcher, and a
missing distribution fails before any test command. Before and after execution it
binds a deterministic hash plus file/directory counts for the complete installed
Gradle tree, rejecting a reparse point at every enumerated level. The exact JVM
selected by `JAVA_HOME` (or `PATH` when unset) must be Java 21. Nonempty
`_JAVA_OPTIONS`, `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `JAVA_OPTS`, `GRADLE_OPTS`,
`ORG_GRADLE_PROJECT_*`, user Gradle properties, and user init scripts fail closed.
It never downloads, copies, extracts, redistributes, or records the filesystem path
of the JAR. Its sanitized report has an exact property set containing only SHA-256,
byte size, declared plugin name/version, selected public event/accessor names, fixed
coverage booleans, and the structural-preflight limitation.

The absolute JAR path is necessarily passed to the local Gradle test JVM as a
system property and can therefore be visible in the local process command line
for the duration of the preflight. It is not persisted in `report.json` or
`binding.json`.

A successful execution also writes a path-free `binding.json` beside the report.
That exact-schema sidecar binds the artifact and locked report digest to a
deterministic manifest of every repository file except `.git`, `.gradle`, and any
directory named `build`, plus the complete installed Gradle-tree manifest and the
selected Java 21 executable identity. The execution path rejects a report reparse
point, validates the report through one read-locked handle, creates the binding
without overwriting an existing entry, validates it through another read-locked
handle, and rehashes both handles before releasing them.
`-ReportOnly` requires the operator-recorded `-ArtifactSha256`, refuses old reports
without this binding, rejects unknown JSON properties and network/reparse evidence
paths, holds the report and binding files open while rehashing them, and by default
accepts timestamps no older than 60 minutes. An operator may select a smaller window
or increase it up to 1440 minutes with
`-MaximumReportAgeMinutes`; this is a local freshness check, not a signature or
license authenticity proof.

A passing report is only structural preflight: it deliberately records
`paper_process_coverage=false`, `licensed_plugin_enablement_coverage=false`, and
`real_behavior_event_delivery_coverage=false`. Actual Paper enablement and a real
licensed Vulcan event remain an operator release gate because the proprietary
artifact and license configuration cannot be redistributed with MCAce.

The retained [Vulcan 2.9.0 evidence](evidence/vulcan-licensed-api-preflight-2026-08-13.json)
records a successful exact-hash structural API preflight and ReportOnly
revalidation that were contemporaneous with its bound source snapshot. It is
historical retained evidence only. A current-source `-ReportOnly` check now fails
closed because the source manifest has changed, so current-source structural
revalidation remains pending. Its `STRUCTURAL_PREFLIGHT_ONLY` limitation and false
Paper-enable/real-event coverage booleans remain authoritative; it is neither
current-source compatibility proof, Paper runtime proof, nor release-ready evidence.

An isolated enablement harness is also available, but has not been executed:

```powershell
.\scripts\vulcan-paper-enablement-smoke.ps1 -Execute `
  -VulcanJar '<direct absolute licensed JAR path>' -VulcanSha256 '<reviewed sha256>' `
  -PaperJar '<direct absolute Paper 1.21.11 JAR path>' -PaperSha256 '<reviewed sha256>' `
  -MCAceJar '<direct absolute MCAce Paper JAR path>' -MCAceSha256 '<reviewed sha256>' `
  -PreparedRoot '<direct absolute prepared Paper root>' `
  -PreparedManifestSha256 '<reviewed prepared runtime manifest sha256>' `
  -AllowTemporaryPaperRemap -NetworkPolicy DenyAll `
  -NetworkIsolationAttested
```

This command executes proprietary licensed code and explicitly permits Paper to
create a temporary remapped derivative inside a disposable run root. Run it only
after the operator has independently enforced a deny-all OS/network boundary; the
script records that attestation but deliberately reports
`network_isolation_os_verified_by_script=false`. On a successful execution it
would directly reference the Vulcan and MCAce JARs rather than copying them,
delete the isolated server root including remapped/private-key/log material, and
retain only a sanitized report. The prepared runtime tree is not self-authorizing:
the caller must pin its reviewed manifest, and the wrapper verifies the source,
isolated copy, and post-run source against that pin. It also rejects any creation
or mutation of `.paper-remapped` under the three original artifact parent directories.
The current enablement wrapper is explicitly JDK 21, so its reviewed server
input must be the current Paper 1.21.11 asset/prepared tree. It does not establish
26.x Vulcan coverage. The historical Vulcan record remains current-source-ineligible.
A pass proves Paper process coverage, licensed-plugin enablement, and MCAce listener
registration. Its schema fixes `real_behavior_event_delivery_coverage=false`, so
one genuine bounded Vulcan-triggered event remains a separate human/driver gate;
constructing an event in MCAce or a test observer is not acceptable evidence.
That second gate is now encoded, but remains unexecuted, in
`scripts/vulcan-genuine-event-smoke.ps1`. It requires the same reviewed artifact and
prepared-runtime pins, deny-all/network-isolation attestations, an expected player,
and explicit attestations that the trigger is external and no synthetic event was
injected. It waits for exactly one loopback-delivered `BEHAVIOR_HIGH_RISK` event with
origin `SERVER_CONFIRMED`, source `vulcan-adapter`, the reviewed provider version,
non-empty check/stable-check fields, and `flag_count >= 1`. The sanitized result does
not retain the player UUID, check values, paths, PIDs, ports, or raw content. Neither
the human trigger origin nor OS isolation is independently proven by the script.
The cleanup field is deliberately named `remaining_marker_process_count`; it
proves zero process command lines bearing the unique run marker, not OS-level
job-object ownership of arbitrary subprocesses.

The PowerShell lock and report-hash equality bind the retained result to the same
artifact bytes, but the Java structural inspector necessarily opens the supplied
path itself. This preflight does not claim a Windows volume/file-ID proof across
those Java path opens; that stronger identity proof would require a gate API
change and remains outside this wrapper-only hardening.
