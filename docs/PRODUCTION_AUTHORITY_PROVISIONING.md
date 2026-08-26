# Production `SERVER_CONFIRMED` authority provisioning (V4 evidence contract)

`scripts/provision-production-authority.ps1` creates the offline key/configuration
freeze used by the Paper/Folia to Velocity/Bungee `SERVER_CONFIRMED` authority
channel. The provisioner is compatible with PowerShell 7 and Windows PowerShell
5.1 and fixes the action ceiling to `MONITOR`.

Provisioning and release evidence are deliberately separate operations:

1. the provisioner generates only the backend and selected-proxy Ed25519 private
   keys needed by the runtime;
2. an independent capture supervisor owns its Ed25519 private key outside the
   repository and outside the provisioned output;
3. the provisioner consumes only the supervisor's public descriptor plus an
   out-of-band approved SHA-256 pin; and
4. `production-authority-process-evidence.ps1` later validates the raw signed
   grant/observation frames and the independent supervisor receipt.

The provisioner **never generates, copies, saves, or prints a supervisor private
key**. A fixture descriptor, a repository-contained descriptor, a self-selected
pin, or any descriptor which says `test_fixture=true` is terminally rejected.

## Required external inputs

### Capture-supervisor public descriptor

The independently operated capture supervisor supplies a canonical UTF-8 JSON
document with this exact schema:

```json
{
  "schema": "MCACE_PRODUCTION_AUTHORITY_CAPTURE_SUPERVISOR_PUBLIC_DESCRIPTOR_V1",
  "artifact_class": "EXTERNAL_RELEASE_CAPTURE_SUPERVISOR_PUBLIC_ROOT",
  "algorithm": "ED25519",
  "key_id_sha256": "<sha256 of X.509 SubjectPublicKeyInfo DER>",
  "public_key_der_base64": "<canonical DER bytes>",
  "test_fixture": false
}
```

The descriptor must live outside the MCAce repository. Its approved hash comes
from an out-of-band reviewer and must be present in the process environment:

```powershell
$env:MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256 = `
  '<reviewer-approved lowercase sha256>'
```

The same value is passed as
`-ExpectedCaptureSupervisorPublicDescriptorSha256`. Passing a value on the CLI
does not approve it: the CLI value, descriptor bytes, and environment pin must
all match.

### Pinned, application-local OpenSSL runtime

OpenSSL is not resolved from `PATH`, and pinning `openssl.exe` alone is not an
acceptable runtime identity. Provisioning and signing are Windows x64
operations. Supply an absolute application-local executable path, the reviewed
SHA-256 of those exact executable bytes, and a separately reviewed runtime
manifest outside the runtime directory:

```powershell
$openSsl = 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'
$openSslSha256 = (Get-FileHash -LiteralPath $openSsl -Algorithm SHA256).Hash.ToLowerInvariant()
$openSslRuntimeManifest = 'C:\ReleaseRoots\mcace-openssl-runtime-v1.json'
$openSslRuntimeManifestSha256 = (Get-FileHash -LiteralPath `
  $openSslRuntimeManifest -Algorithm SHA256).Hash.ToLowerInvariant()
```

The runtime directory has this shape:

```text
<runtime-root>/
  openssl.exe
  <every application-local DLL used by this build>
  openssl.cnf
  providers/
    <every reviewed provider DLL>
```

`openssl.cnf` is exactly UTF-8 without BOM and contains
`# MCAce pinned empty OpenSSL configuration v1` plus one LF. The manifest is
strict JSON with exact properties and ordinally sorted, unique leaf names:

```json
{
  "schema": "MCACE_OPENSSL_RUNTIME_MANIFEST_V1",
  "artifact_class": "REVIEWED_OPENSSL_RUNTIME",
  "platform": "windows-x64",
  "executable_relative_path": "openssl.exe",
  "files": [
    {"relative_path":"libcrypto-3-x64.dll","role":"APPLICATION_LOCAL_DLL","size_bytes":123,"sha256":"<lowercase sha256>"},
    {"relative_path":"openssl.cnf","role":"CONFIG","size_bytes":46,"sha256":"ea95eeb8ee1e4e5241dbece9012a2b394ef8ef0b8d58af0f4eeaf40f8422de8b"},
    {"relative_path":"openssl.exe","role":"EXECUTABLE","size_bytes":123,"sha256":"<lowercase sha256>"},
    {"relative_path":"providers/default.dll","role":"PROVIDER_MODULE","size_bytes":123,"sha256":"<lowercase sha256>"}
  ],
  "test_fixture": false
}
```

Use the real reviewed sizes and hashes; the numbers above are schema examples.
The manifest must enumerate the **exact** recursive file set, including at
least one application-local DLL and one provider module. Extra files, missing
files, duplicate/non-ordinal entries, unknown roles, a manifest stored inside
the runtime, or any leaf/size/hash mismatch fail closed. The runtime directory
must have protected inheritance, be owned by the current account or `SYSTEM`,
and grant full control only to that account and `SYSTEM`.

Before the first invocation, every runtime file is opened read-only without
delete/write sharing and every directory component is pinned by a native
no-delete-share handle. Those handles remain open across all OpenSSL work.
Each operation rechecks the exact set, manifest bytes, file IDs, sizes, and
hashes before and after execution. OpenSSL is launched by
`System.Diagnostics.ProcessStartInfo` with the runtime directory as its fixed
working directory and a cleared, minimum child environment: only the required
Windows/TEMP values, an application-local `PATH`, the exact `OPENSSL_CONF`, and
the exact `OPENSSL_MODULES` are restored. Parent `PATH`, provider/config
overrides, loader variables, and ambient process state are not inherited.

## Example

```powershell
& .\scripts\provision-production-authority.ps1 `
  -OutputRoot 'C:\MCAceSecrets\production-authority-2026-08-26' `
  -ProxyInstanceId 'proxy-sg-1' `
  -BackendInstanceId 'paper-survival-sg-1' `
  -RegisteredBackend 'survival' `
  -ProfileName 'production-quorum' `
  -ProxyPlatform 'VELOCITY' `
  -GrimProviderId 'grim' `
  -GrimTrustDomainId 'grim-engine' `
  -GrimVersion '2.3.74-155abaf' `
  -GrimStableCheckFamily 'movement-stable' `
  -GrimThreshold 5 `
  -VulcanProviderId 'vulcan' `
  -VulcanTrustDomainId 'vulcan-engine' `
  -VulcanVersion '2.9.0' `
  -VulcanStableCheckFamily 'movement-stable' `
  -VulcanThreshold 3 `
  -RequiredIndependentDomains 2 `
  -MaximumProviderWindowMs 10000 `
  -CooldownMs 5000 `
  -ObservationTtlMs 30000 `
  -GrantTtlMs 30000 `
  -JournalQuotaBytes 8388608 `
  -ActionCeiling MONITOR `
  -CaptureSupervisorPublicDescriptorPath 'C:\ReleaseRoots\mcace-authority-supervisor.json' `
  -ExpectedCaptureSupervisorPublicDescriptorSha256 `
      $env:MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256 `
  -OpenSslPath $openSsl `
  -ExpectedOpenSslSha256 $openSslSha256 `
  -OpenSslRuntimeManifestPath $openSslRuntimeManifest `
  -ExpectedOpenSslRuntimeManifestSha256 $openSslRuntimeManifestSha256
```

The executable contract requires:

- exactly provider IDs `grim` and `vulcan`;
- distinct trust-domain IDs and exactly two required independent domains;
- thresholds in `1..256`;
- provider window in `1..30000` ms;
- both grant and observation TTLs exactly `30000` ms;
- bounded journal quota; and
- action ceiling exactly `MONITOR`.

These constraints are validated rather than merely recorded as caller
booleans.

## Generated layout

```text
<OutputRoot>/
  freeze-manifest.json
  evidence-supervisor/
    capture-supervisor-public-descriptor.json   # public bytes only
  paper/
    authority-snippet.yml
    proxy-public-key.txt
    authority/
      backend-private-key.pk8
      backend-public-key.txt
      issuance.log
  velocity/
    authority.properties
    authority/backend-public-key.txt
    identity/                                   # selected platform only
      server-private-key.pk8
      server-public-key.txt
  bungeecord/
    authority.properties
    authority/backend-public-key.txt
    identity/                                   # selected platform only
      server-private-key.pk8
      server-public-key.txt
```

Only the selected proxy receives `identity/`. The unselected proxy directory
contains review/configuration material but no grant-signing private key. The
backend and proxy Ed25519 key IDs are SHA-256 over canonical X.509
SubjectPublicKeyInfo DER and must differ.

`issuance.log` begins with exactly:

```text
MCACE_SERVER_AUTHORITY_ISSUANCE_JOURNAL_V3
```

`freeze-manifest.json` uses
`mcace-production-authority-freeze/v3`. It binds the artifact source commit,
external supervisor descriptor hash/key ID, backend/proxy key IDs, selected
proxy topology, provider profile, TTLs, journal quota, enabled Grim/Vulcan
adapter freeze, and `MONITOR`. Its evidence-supervisor object explicitly records
`private_key_present=false`.

The output is written to a sibling staging directory and committed with one
directory rename. The requested final directory must be new, absolute, outside
the repository, and reached through no symbolic link, junction, or other
reparse point. Before any private key is generated, the staging directory is
given a protected, non-inheriting ACL granting full control only to the current
account and `SYSTEM`; the committed output keeps that ACL. Every sensitive
input is read twice through one exclusive file handle with bounded length and
stable native identity. A failure removes the staging directory and leaves no
partial final root.

## Deployment boundary

1. Keep the output outside source control and ordinary backup/export paths.
2. Deploy `paper/authority/`, `paper/proxy-public-key.txt`, and merge the
   generated Paper snippet without creating duplicate YAML roots.
3. Deploy only the proxy selected by `topology.selected_proxy_platform`.
4. Preserve the backend/proxy private-key ACLs (`current user + SYSTEM` on
   Windows, mode `0600` on non-Windows).
5. Keep the independent supervisor private key on the external capture system;
   it is never a deployment artifact.
6. Run the real process capture in an isolated topology and keep automatic
   actions at zero.

Generating the bundle does not install or enable it. Repository defaults remain
disabled.

## V4 evidence handoff

The Formal collector no longer accepts a receipt prepared before repository
validation. It first performs the complete raw/provider/process/JAR/OpenSSL/pin
validation, creates an exact payload, then atomically publishes an external
signing request. Only an independent signer may create the requested receipt.
The collector waits in 250 ms intervals for a bounded period, re-reads the
unchanged request through an exclusive no-follow handle, verifies the receipt
against the request's exact payload bytes, and only then commits a package.

Create an empty exchange directory outside the repository, release bundle, and
future output package. Both leaves must be absolute, different, and initially
absent:

```powershell
$exchange = 'C:\MCAceExternalExchange\authority-2026-08-26-attempt-01'
New-Item -ItemType Directory -Path $exchange | Out-Null
$request = Join-Path $exchange 'signing-request.json'
$receipt = Join-Path $exchange 'supervisor-receipt.json'

& .\scripts\production-authority-process-evidence.ps1 `
  -Mode Formal `
  -CaptureManifestPath 'C:\MCAceCapture\attempt-01\raw-capture-manifest.json' `
  -OutputDirectory 'C:\MCAceEvidence\authority-v4-attempt-01' `
  -CaptureSupervisorPublicDescriptorPath 'C:\ReleaseRoots\mcace-authority-supervisor.json' `
  -ExpectedCaptureSupervisorPublicDescriptorSha256 `
      $env:MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256 `
  -SupervisorSigningRequestPath $request `
  -SupervisorReceiptPath $receipt `
  -SupervisorReceiptWaitSeconds 600 `
  -ReleaseBundleRoot 'C:\MCAceRelease\v0.0.1-exact-A' `
  -OpenSslPath $openSsl `
  -ExpectedOpenSslSha256 $openSslSha256
```

After prevalidation the producer prints exactly one handoff marker:

```text
PRODUCTION_AUTHORITY_SIGNING_REQUEST_READY|request=<absolute path>|receipt=<absolute path>|attempt=<uuid>|challenge=<sha256>
```

The request schema is
`MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_SIGNING_REQUEST_V1`. It contains the
expected receipt payload as `signed_payload_base64`, its exact SHA-256 and byte
length, the reviewed descriptor pin/key ID, capture and operation IDs, source
and artifact commits (capture commit A), product version, the three exact
server JAR hashes/sizes, raw-manifest/root/frame-set/provider/profile/topology/
process-ledger/issuance-journal commitments, a fresh 32-byte challenge, an
issued time, a not-after time no more than 15 minutes later, and the absolute
receipt output path. It contains no private key and does not contain its own
hash, so there is no signing cycle.

On the isolated signer host, review the request, its exact SHA-256, descriptor
pin, signer key ID, receipt destination, release identity, JAR commitments,
provider set, monitor-only ceiling, and exchange window before signing. Use the
repository signer below from the reviewed source commit. The private-key bytes
never enter the command line, request, repository, capture, or output package:

```powershell
$exchangeRoot = 'C:\MCAceExternalExchange\authority-2026-08-26-attempt-01'
$requestPath = Join-Path $exchangeRoot 'signing-request.json'
$receiptPath = Join-Path $exchangeRoot 'supervisor-receipt.json'

# Freeze this exact value only after independent operator review. Do not derive
# an approval value inside an unattended signer invocation.
$approvedRequestSha256 = '<reviewed-64-lowercase-hex-request-sha256>'

& .\scripts\sign-production-authority-receipt.ps1 `
  -RequestPath $requestPath `
  -ExpectedRequestSha256 $approvedRequestSha256 `
  -ApprovedRequestSha256 $approvedRequestSha256 `
  -ReceiptPath $receiptPath `
  -ExpectedDescriptorPath 'C:\ReleaseRoots\mcace-authority-supervisor.json' `
  -ExpectedDescriptorSha256 $approvedDescriptorSha256 `
  -ExpectedSignerKeyIdSha256 $approvedSignerKeyIdSha256 `
  -PrivateKeyPath 'C:\MCAceSignerPrivate\authority-supervisor.pk8' `
  -OpenSslPath 'C:\MCAceSignerTools\openssl.exe' `
  -ExpectedOpenSslSha256 $approvedSignerOpenSslSha256 `
  -OpenSslRuntimeManifestPath 'C:\ReleaseRoots\mcace-signer-openssl-runtime-v1.json' `
  -ExpectedOpenSslRuntimeManifestSha256 $approvedSignerRuntimeManifestSha256 `
  -AllowedExchangeRoot $exchangeRoot
```

`-ReceiptPath` is an independent operator argument. The signer verifies that
the request names that same destination, but never uses the request value as a
write primitive. The request field must already be the exact canonical,
absolute string returned by `GetFullPath`; relative paths, `.`/`..` spellings,
alternate aliases, or a merely equivalent normalized path are rejected.
Request and receipt must be distinct **direct leaves** of the exact no-reparse
`-AllowedExchangeRoot`; nested descendants are rejected. The descriptor,
PKCS#8 private key, runtime manifest, pinned OpenSSL runtime, and replay ledger
must remain outside that exchange. The private-key parent and OpenSSL runtime
both use the protected current-user-plus-`SYSTEM` ACL contract described above.

At signer start, every component from the volume root through
`-AllowedExchangeRoot` is opened without delete sharing. Receipt creation uses
`NtCreateFile` relative to the already pinned root handle, performs exclusive
create/write-through/readback/single-link validation, and installs the final
leaf with `NtSetInformationFile(FileRenameInformation)` relative to that same
root handle. A concurrent rename or junction-swap prerequisite therefore
fails; the signer never re-resolves an attacker-replaceable parent for the
create or rename.

The fixed replay ledger
`.mcace-production-authority-v4-replay-v2.tsv` is created beside the private
key, locked across processes, and flushed before receipt installation. It has
two independent domain-separated indexes: one for `(signer key ID,
operation_attempt_id)` and one for `(signer key ID, challenge_nonce_base64)`.
Reuse of either value is terminal even when the other value is fresh. A named
mutex serializes the read/check/append/install transaction; concurrent
same-operation/different-challenge and different-operation/same-challenge
requests produce at most one receipt. Treat a burned ledger entry without a
receipt as a failed attempt and generate a new capture request rather than
deleting or editing the ledger.

The signer rejects unknown or duplicate fields, scalar/array/integer coercion,
non-canonical payload bytes, every request/payload cross-binding mismatch,
future or expired windows, an unapproved request hash, wrong descriptor/key/
OpenSSL pins, private/public key mismatch, reparse or out-of-allowlist paths,
request/tool/key mutation, receipt pre-creation, replay, and concurrent use. It
derives the Ed25519 public key from the signer-local private key, compares its
exact DER bytes with the pinned descriptor, signs only the already reviewed
canonical payload bytes, self-verifies the signature, re-reads all trusted
inputs, and then performs CreateNew + write-through flush + atomic receipt
installation through the pinned directory handle. The signer also holds the
same exact OpenSSL runtime manifest, DLL/provider/config file locks, native
directory locks, minimum child environment, and pre/post validation described
for the provisioner.

The receipt keeps the existing
`MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_V1` envelope. Its Ed25519
signature covers exactly the request's payload bytes; rebuilding a semantically
similar JSON object is rejected. A missing receipt, bad pin/signature, expired
or future interval, replayed receipt/challenge, request mutation, path alias,
reparse path, or receipt committed before successful validation fails closed
and leaves the output directory absent. `-SupervisorReceiptPath` immediate mode
is retained only for the explicitly synthetic `-Mode Fixture` contract; it is
not a Formal release-grade path.

`not_after` / receipt `expires_at` is an **exchange TTL**, not the lifetime of
the durable evidence. During the live handoff the producer requires the receipt
to arrive while `UtcNow < expires_at`, and the generated report/binding/commit
timestamp must fall in `[issued_at, expires_at)`. Later validation proves that
historical ordering plus the Ed25519 signature and immutable commitments; it
does not invalidate an already committed package merely because wall-clock time
has advanced. `-RequireCurrentlyValidReceipt` is therefore an explicit
immediate-stage switch for collection/publication acceptance, not a default for
later protected CI, tag, or archive revalidation.

The formal collector ultimately consumes the external descriptor, signed
receipt, raw capture manifest, raw event ledgers, process ledger, issuance
journal, artifact manifest/bytes, and actual signed protobuf frames. A
successful prepublication package contains 14 canonical root documents plus an exact ten-file
`artifacts/` directory:

```text
artifact-manifest.json
binding.json
capture-supervisor-public-descriptor.json
commit.json
freeze-manifest.json
issuance-journal.log
paper-events.jsonl
process-ledger.json
provider-events.jsonl
proxy-events.jsonl
raw-capture-manifest.json
raw-frames.jsonl
report.json
supervisor-receipt.json
artifacts/                       # exact bytes referenced by artifact manifest
```

The producer deliberately emits `release_eligible=false`. Only the native
publisher may create a V4 index with `release_eligible=true`, and only after it
revalidates the complete raw package, the immediate exchange window, the approved
descriptor pin, pinned OpenSSL, and the exact V4 release bundle in a private
staging directory. Once the report/binding/commit and index are durably
committed inside that window, their signed historical validity does not expire.

The packaged `release_bundle` describes the capture bundle at artifact commit A
(`source_commit=A`, `artifact_source_commit=A`). After publication creates the
evidence-only descendant R, readiness separately validates the protected
`source_commit=R`, `artifact_source_commit=A` bundle and requires its Paper,
Velocity, and BungeeCord JARs to equal the capture-bound bytes. The two manifest
hashes are not equal because their `source_commit` metadata differs.

Release readiness then performs an independent V4 validation pass. It requires
`MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256`,
`MCACE_RELEASE_AUTHORITY_OPENSSL_PATH`, and
`MCACE_RELEASE_AUTHORITY_OPENSSL_SHA256` from the protected environment; reads
the 14 root documents and ten artifacts through exclusive, double-read,
no-follow handles; re-runs `production-authority-process-evidence.ps1
-ValidatePackageRoot`; checks the exact protected Paper, Velocity, and
BungeeCord JAR bytes; and rejects any sibling V4 index that reuses the signed
operation attempt or supervisor challenge. Readiness validates that capture,
receipt issuance, package commit, and publication occurred in the signed order;
it must not apply the old exchange deadline to the current wall clock. This
keeps tag/release reruns deterministic while preserving the short live-signing
anti-replay window.

## Regression tests

```powershell
pwsh -NoProfile -File .\scripts\test-provision-production-authority.ps1
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File .\scripts\test-provision-production-authority.ps1

pwsh -NoProfile -File .\scripts\test-production-authority-process-evidence.ps1
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File .\scripts\test-production-authority-process-evidence.ps1

pwsh -NoProfile -File .\scripts\test-sign-production-authority-receipt.ps1
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File .\scripts\test-sign-production-authority-receipt.ps1

pwsh -NoProfile -File .\scripts\test-publish-native-release-evidence.ps1
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File .\scripts\test-publish-native-release-evidence.ps1

pwsh -NoProfile -File .\scripts\test-release-readiness.ps1
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass `
  -File .\scripts\test-release-readiness.ps1
```

The tests create real Ed25519 frames and signatures in a temporary, explicitly
synthetic fixture. They exercise the external request/wait/receipt exchange and
cover missing receipt, request/payload mutation, bad descriptor pin/signature,
expired/future receipt windows, receipt replay, path alias/reparse, absence of
private-key material, commit-before-receipt, wrong keys/profile/session,
commitment mismatch, missing frames, replayed nonce, old schemas, fake JARs,
runtime DLL/config/provider mutation, runtime exact-set additions, permissive
runtime ACLs, independent operation/challenge replay (including concurrent
pairs), allowed-root rename/junction-swap prerequisites, and complete package
revalidation. Fixture success proves validator behavior only; it is not
external production evidence and cannot close the release gate.

The PR-only Ubuntu diagnostic emits
`MCACE_UBUNTU_OPENSSL_RUNTIME_PIN` and a canonical
`MCACE_UBUNTU_OPENSSL_RUNTIME_V1` manifest. It covers `/usr/bin/openssl`, every
absolute dependency resolved by `ldd`, each canonical path, exact byte size,
SHA-256, owning Debian package/version, and the GitHub-hosted `ImageOS` and
`ImageVersion`. Protected release CI requires exact environment pins in:

- `MCACE_AUTHORITY_OPENSSL_SHA256`;
- `MCACE_AUTHORITY_OPENSSL_RUNTIME_MANIFEST_SHA256`;
- `MCACE_AUTHORITY_RUNNER_IMAGE_OS`; and
- `MCACE_AUTHORITY_RUNNER_IMAGE_VERSION`.

Protected CI rejects symlinks, non-root-owned or group/other-writable runtime
files, missing libraries/package ownership, a changed resolved set, a changed
runner image, and any pre/post-readiness manifest drift. Release-only steps
explicitly require `success()` and
`needs['windows-contracts'].result == 'success'`; the first `build` step also
fails unless the predecessor result is exactly `success`, so `failure`,
`cancelled`, and `skipped` cannot enter release work. Branch protection should
still require both `build` and `windows-contracts` so a future workflow refactor
cannot silently weaken the Windows signer and release-contract gate.
