# Server Version Process Matrix Evidence V4

## Status and purpose

Matrix V4 is the first Matrix schema that is structurally capable of satisfying
`server_matrix_exact_source`. It covers the exact twelve
`version x backend x proxy` processes:

- Minecraft `1.21.11`, `26.1.2`, and `26.2`;
- Paper and Folia backends;
- Velocity and BungeeCord proxies.

V4 replaces the unsigned V2/V3 release path. V2 and the documented
[V3 historical contract](SERVER_VERSION_MATRIX_EVIDENCE_V3.md) remain useful
diagnostics, but `release-readiness.ps1` rejects both with
`MCACE_RELEASE_MATRIX_V2_V3_NOT_RELEASE_ELIGIBLE`; changing a Boolean inside a
legacy document cannot promote it.

A V4 result is release-grade only after all of the following are true:

1. the producer executes all twelve real process cases and observes cleanup;
2. an exact protected `MCACE_RELEASE_BUNDLE_V4` already exists;
3. an out-of-repository supervisor trust root is pinned by a protected process
   environment variable;
4. the producer freezes report, binding, raw manifest, twelve raw reports, case
   process identities, release artifacts, and server JARs in a signing request;
5. an independent external supervisor returns a detached, unexpired RSA receipt;
6. the producer verifies the receipt and writes `commit.json` last;
7. the publisher and release-readiness independently re-read and verify the full
   chain, including replay and TOCTOU checks.

The implementation and regression fixtures do **not** by themselves claim that a
real production supervisor has signed a release attempt. A real V4 index/native
package, real protected pin, and still-valid detached receipt must exist at the
exact release commit.

## Schemas and signing domains

| Role | Exact schema/domain |
|---|---|
| report | `MCACE_SERVER_VERSION_PROCESS_MATRIX_REPORT_V4` |
| binding | `MCACE_SERVER_VERSION_PROCESS_MATRIX_BINDING_V4` |
| commit | `MCACE_SERVER_VERSION_PROCESS_MATRIX_COMMIT_V4` |
| raw manifest | `MCACE_SERVER_VERSION_PROCESS_MATRIX_RAW_MANIFEST_V1` |
| published index | `MCACE_SERVER_VERSION_PROCESS_MATRIX_EVIDENCE_INDEX_V4` |
| supervisor signing request | `MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_SIGNING_REQUEST_V1` |
| detached supervisor receipt | `MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_RECEIPT_V1` |
| out-of-band trust root | `MCACE_SERVER_VERSION_MATRIX_SUPERVISOR_TRUST_ROOT_V1` |
| ordered raw root | `MCACE_SERVER_VERSION_PROCESS_MATRIX_RAW_SET_V1` |
| case/process set | `MCACE_SERVER_VERSION_PROCESS_MATRIX_CASE_RUNTIME_SET_V1` |
| process incarnation | `MCACE_SERVER_VERSION_PROCESS_MATRIX_PROCESS_INCARNATION_V1` |
| six release JAR set | `MCACE_SERVER_VERSION_PROCESS_MATRIX_RELEASE_ARTIFACT_SET_V1` |
| three Matrix server JAR set | `MCACE_SERVER_VERSION_PROCESS_MATRIX_PRODUCT_JAR_SET_V1` |
| receipt signing preamble | `MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_RECEIPT_SIGNING_V1` |

The signature algorithm is exactly `RSA_PKCS1_SHA256`. The accepted public
modulus length is 2048 through 4096 bits. No producer, publisher, repository,
release bundle, published evidence directory, or readiness parameter accepts a
supervisor private key.

## Trust root and protected pin

The trust root is a JSON file stored outside the repository, native input
package, output evidence tree, release bundle, and supervisor exchange tree:

```json
{
  "schema": "MCACE_SERVER_VERSION_MATRIX_SUPERVISOR_TRUST_ROOT_V1",
  "artifact_class": "OUT_OF_BAND_PINNED_MATRIX_SUPERVISOR_TRUST_ROOT",
  "key_id": "matrix-supervisor-production-2026-01",
  "algorithm": "RSA_PKCS1_SHA256",
  "modulus_base64": "<unsigned big-endian RSA modulus>",
  "exponent_base64": "AQAB",
  "test_fixture": false
}
```

Its raw-file SHA-256 must equal both:

- the explicit `-ExpectedSupervisorTrustRootSha256` or
  `-ExpectedMatrixSupervisorTrustRootSha256` argument; and
- the process-scoped protected pin
  `MCACE_RELEASE_APPROVED_MATRIX_SUPERVISOR_TRUST_ROOT_SHA256`.

Missing, malformed, caller-only, mismatched, self-hosted, reparse-point, and
`test_fixture=true` trust roots fail closed. The trust root is read with a
no-follow file identity, exclusive handle, double same-handle byte read, and a
final stable re-read after signature verification.

## Producer/external-supervisor protocol

The producer does not sign its own evidence. After completing twelve cases it:

1. freezes `raw/`, `raw-manifest.json`, `report.json`, and `binding.json` in a
   same-volume staging directory;
2. creates a random 128-bit `operation_attempt_id` and random 256-bit
   `challenge_nonce` using `RandomNumberGenerator`;
3. creates a signing request with a maximum receipt window of 30 minutes (the
   producer currently requests 15 minutes);
4. writes the same request bytes to
   `<exchange>/request-<operation_attempt_id>.json`;
5. prints `SERVER_VERSION_MATRIX_SIGNING_REQUEST_READY|...` and waits for
   `<exchange>/receipt-<operation_attempt_id>.json`;
6. validates provenance, all frozen bindings, expiry, and the RSA signature;
7. copies the exact receipt bytes into staging;
8. re-reads the protected bundle and trust root; and
9. writes `commit.json` last, then publishes the directory by same-volume rename.

The external signer must operate from a separately controlled environment. It
must verify the request and the referenced process evidence before producing a
receipt. The private key remains in that environment.

### Signing request coverage

The request binds all of these values and arrays:

- release source commit, artifact source commit, and product version;
- attempt ID, challenge, challenge issue time, and receipt deadline;
- raw byte SHA-256 and length for report, binding, and raw manifest;
- ordered root for exactly twelve raw reports;
- twelve ordered case runtime commitments;
- every cleanup PID as a role-labelled process-incarnation commitment;
- invocation start/finish times, invocation-log hash, raw-report hash/length,
  cleanup count, zero remaining processes, and cleanup observation;
- `MCACE_RELEASE_BUNDLE_V4` manifest and `SHA256SUMS` hashes/lengths;
- the ordered six-JAR release artifact set;
- the three Matrix server JAR bindings (`velocity`, `bungee`, `paper`);
- supervisor trust-root hash, key ID, and signature algorithm.

A process incarnation hashes `case_id`, role, PID, invocation time bounds,
proxy JAR SHA-256, and backend JAR SHA-256 under its own domain. A recycled PID
therefore cannot stand in for a different observed process without changing the
signed case/runtime root.

### Detached receipt

The receipt has exact properties. It repeats every scalar commitment from the
request, adds:

```text
artifact_class=EXTERNALLY_SIGNED_MATRIX_SUPERVISOR_RECEIPT
source_mode=EXTERNAL_MATRIX_SUPERVISOR
supervisor_independent=true
test_fixture=false
signer_key_id=<pinned key id>
signer_trust_root_sha256=<pinned trust-root SHA-256>
signature_algorithm=RSA_PKCS1_SHA256
signed_at=<RFC3339 timestamp>
expires_at=<exact request receipt_not_after>
signature_base64=<RSA signature>
```

The signed payload is UTF-8 without BOM. It starts with the receipt signing
preamble, then emits every receipt property except `signature_base64` in the
fixed schema order as `name=value` plus LF. Booleans are lowercase
`true`/`false`; integers use invariant decimal formatting. Newlines in names or
values are rejected.

The publisher and readiness reject an invalid signature, wrong key/root,
self-supervision, fixture receipt, dependent supervisor, expired receipt,
attempt/challenge mismatch, receipt/request binding mismatch, and replay of
either an attempt ID or challenge nonce in another V4 index.

## Exact native package

A committed V4 package has exactly seven root entries:

```text
<evidence-id>/
  report.json
  binding.json
  commit.json
  raw-manifest.json
  supervisor-signing-request.json
  supervisor-receipt.json
  raw/
    1.21.11-paper-velocity.json
    1.21.11-paper-bungee.json
    1.21.11-folia-velocity.json
    1.21.11-folia-bungee.json
    26.1.2-paper-velocity.json
    26.1.2-paper-bungee.json
    26.1.2-folia-velocity.json
    26.1.2-folia-bungee.json
    26.2-paper-velocity.json
    26.2-paper-bungee.json
    26.2-folia-velocity.json
    26.2-folia-bungee.json
```

No extra root entry, missing raw report, nested raw directory, path escape,
case-fold collision, alternate separator, reparse point, BOM, duplicate JSON
property, or changed descriptor byte set is accepted. `commit.json` binds the
request and receipt hashes/lengths and is the final producer write.

## Release bundle and server JAR binding

The V4 index and receipt bind the exact eight-entry release bundle:

```text
release-manifest.properties
SHA256SUMS
mcace-client-fabric-1.21.11.jar
mcace-client-fabric-26.1.2.jar
mcace-client-fabric-26.2.jar
mcace-server-velocity.jar
mcace-server-bungeecord.jar
mcace-server-paper.jar
```

The six JARs are hashed as an ordered release set. The three server JARs are
also hashed as a role/file/native-path set and must match:

1. the protected release bundle;
2. `binding.current.product_jars` from the executed Matrix source; and
3. every case's proxy/backend plugin JAR identity.

The release commit and artifact-producing commit are distinct fields. The
artifact commit may be an ancestor of the final commit only when the intervening
delta is limited to README/evidence publication paths accepted by
`Test-SourceProvenance`.

## Commands

Use absolute paths for the external trust root and exchange directory. The
example assumes the exact V4 release bundle is already built and
`$artifactCommit` is the immutable commit that produced the Matrix artifacts.

```powershell
$artifactCommit = (git rev-parse HEAD).Trim().ToLowerInvariant()
$trustRoot = 'C:\MCAceReleaseAuthority\matrix-supervisor-public.json'
$exchange = 'C:\MCAceReleaseAuthority\matrix-exchange'
$bundle = (Resolve-Path 'build\release-bundle').Path
$pin = (Get-FileHash -LiteralPath $trustRoot -Algorithm SHA256).Hash.ToLowerInvariant()

$env:MCACE_ARTIFACT_SOURCE_COMMIT = $artifactCommit
$env:MCACE_MATRIX_RELEASE_BUNDLE_ROOT = $bundle
$env:MCACE_MATRIX_SUPERVISOR_TRUST_ROOT_PATH = $trustRoot
$env:MCACE_MATRIX_SUPERVISOR_EXCHANGE_ROOT = $exchange
$env:MCACE_RELEASE_APPROVED_MATRIX_SUPERVISOR_TRUST_ROOT_SHA256 = $pin

pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/server-version-process-matrix.ps1 `
  -Execute -ExpectedSourceCommit $artifactCommit `
  -ReleaseBundleRoot $bundle `
  -SupervisorTrustRootPath $trustRoot `
  -ExpectedSupervisorTrustRootSha256 $pin `
  -SupervisorExchangeRoot $exchange `
  -SupervisorReceiptWaitSeconds 300
```

The independent supervisor watches the printed request path, verifies it, and
atomically places the detached receipt at the printed receipt path. After the
producer succeeds, locate the final run directory and publish it:

```powershell
$run = Get-ChildItem build\server-version-process-matrix\runs -Directory |
  Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1

pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File scripts/publish-server-version-matrix-evidence.ps1 `
  -ReportPath (Join-Path $run.FullName 'report.json') `
  -BindingPath (Join-Path $run.FullName 'binding.json') `
  -CommitPath (Join-Path $run.FullName 'commit.json') `
  -ReleaseBundleRoot $bundle `
  -ArtifactSourceCommit $artifactCommit `
  -SupervisorTrustRootPath $trustRoot `
  -ExpectedSupervisorTrustRootSha256 $pin
```

After committing the evidence-only publication delta, run readiness with the
same protected pin and external root:

The producer and supervisor documents continue to bind the capture bundle at
artifact commit A. The protected descendant R rebuilds a `R/A` release manifest.
Readiness does not equate those two manifest hashes: it validates the historical
A manifest through the signed receipt, validates the current R manifest
structurally, and requires canonical `SHA256SUMS` plus all six JARs to be exactly
the signed A bytes. Only `README.md`, `README_CN.md`, and `docs/evidence/**` may
differ between A and R.

```powershell
$releaseCommit = (git rev-parse HEAD).Trim().ToLowerInvariant()
$env:MCACE_RELEASE_APPROVED_MATRIX_SUPERVISOR_TRUST_ROOT_SHA256 = $pin
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/release-readiness.ps1 `
  -SourceCommit $releaseCommit `
  -MatrixSupervisorTrustRootPath $trustRoot `
  -ExpectedMatrixSupervisorTrustRootSha256 $pin
```

`ReportOnly` validates an existing complete V4 package without executing or
mutating Matrix processes:

```powershell
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/server-version-process-matrix.ps1 `
  -ReportOnly -ExpectedSourceCommit $artifactCommit `
  -ReleaseBundleRoot $bundle `
  -SupervisorTrustRootPath $trustRoot `
  -ExpectedSupervisorTrustRootSha256 $pin
```

## Regression commands

Run all Matrix and readiness regressions under both engines:

```powershell
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/test-server-version-process-matrix.ps1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/test-server-version-process-matrix.ps1

pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/test-publish-server-version-matrix-evidence.ps1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/test-publish-server-version-matrix-evidence.ps1

pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/test-release-readiness.ps1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/test-release-readiness.ps1
```

The publisher regression covers V2/V3 rejection, signature tampering, expiry,
fixture/dependent/unapproved/self trust, replay, raw/package tampering, reparse
and replacement attempts, bundle/JAR mismatches, and idempotent force publish.
The readiness regression exercises helper-level RSA receipt acceptance, bad
signature, expiry, fixture/dependent receipt rejection, protected-pin failure,
replay rejection, Windows no-follow junction handling, and the A-to-R
evidence-only provenance contract. Publisher fixtures cover the full packaged
document set; the genuine external twelve-process run remains a release gate.
