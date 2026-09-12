# Server Version Process Matrix Evidence V3

> **Historical diagnostic schema.** V3 remains permanently non-release. The
> externally supervised release contract is documented in
> [`SERVER_VERSION_MATRIX_EVIDENCE_V4.md`](SERVER_VERSION_MATRIX_EVIDENCE_V4.md).

## Purpose

`MCACE_SERVER_VERSION_PROCESS_MATRIX_*_V3` replaces the terminally rejected V2
triplet. V3 is a content-bound **executed diagnostic package** for the twelve
`version x backend x proxy` cases:

- Minecraft `1.21.11`, `26.1.2`, and `26.2`;
- Paper and Folia backends;
- Velocity and BungeeCord proxies.

V3 deliberately remains `release_eligible=false`. A caller-controlled success
flag cannot substitute for an independently pinned supervisor signature.

## Exact package

The producer and publisher require this exact shape:

```text
<evidence-id>/
  report.json
  binding.json
  commit.json
  raw-manifest.json
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

No additional file, missing raw report, nested directory, path escape, or
reparse point is accepted. Every JSON file is read as a regular file through a
no-follow identity check, an exclusive locked handle, and two same-handle byte
reads. SHA-256 and byte length are recomputed from those bytes before strict
JSON parsing.

## Cross-bindings

`raw-manifest.json` contains twelve ordered descriptors. Each descriptor binds:

- ordinal and case ID;
- target Minecraft version, backend, and proxy;
- raw schema `4` and canonical `raw/<case-id>.json` path;
- raw SHA-256 and byte length;
- `execution_mode=EXECUTE`, invocation exit code `0`, and invocation-log hash;
- cleanup count, zero remaining processes, and observed cleanup.

The ordered descriptor projection is hashed under domain
`MCACE_SERVER_VERSION_PROCESS_MATRIX_RAW_SET_V1`. That root is repeated and
checked in the report, binding, commit, published index, and raw manifest.
The published index additionally binds both commits separately:

- `source_commit`: exact protected V4 release-bundle commit;
- `artifact_source_commit`: commit that produced the matrix artifacts.

The three server JAR identities must agree across the matrix native-current
binding, structurally valid server JARs, and the exact six-JAR V4 release bundle.
A byte array carrying a `.jar` name is rejected.

## Raw semantic validation

Every raw report is checked independently for the expected platform/version,
forwarding mode, distinct valid ports, successful login/configuration/MCAce
handshake/admission assertions, protocol trace, unique positive cleanup PIDs,
zero remaining run processes, and no limitations. `synthetic`,
`test_fixture`, and `manual_byte_array` markers are rejected.

## Release boundary

The current V3 package contains:

```text
evidence_class=EXECUTED_UNSIGNED_DIAGNOSTIC
independent_supervisor_signature_required=true
independent_supervisor_signature_present=false
release_eligible=false
```

After validating all bytes and cross-bindings, current `release-readiness.ps1`
terminally rejects V3. The only accepted release index schema is:

```text
MCACE_SERVER_VERSION_PROCESS_MATRIX_EVIDENCE_INDEX_V4
```

The V4 contract defines the independent supervisor profile, detached signature,
ordered raw root, commit/JAR/bundle bindings, and external key pinning; see
[`SERVER_VERSION_MATRIX_EVIDENCE_V4.md`](SERVER_VERSION_MATRIX_EVIDENCE_V4.md).
V3 itself never upgrades to release-grade based on booleans inside its package.

## Regression commands

Run both engines on Windows:

```powershell
pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/test-server-version-process-matrix.ps1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/test-server-version-process-matrix.ps1

pwsh -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/test-publish-server-version-matrix-evidence.ps1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File scripts/test-publish-server-version-matrix-evidence.ps1
```

The publisher regression includes negative cases for legacy V2/V3, missing raw
reports, raw marker injection, reparse/path replacement, provenance mismatch,
and a hand-built byte-array fake JAR.
