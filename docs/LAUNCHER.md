# MCAce Launcher trust and atomic update

## Delivered boundary

`mcace-launcher` establishes the file/build portion of Level 2 `TRUSTED`. It does
not claim that a locally patchable Launcher proves its own execution. The next
gate binds a short-lived launch credential into the Fabric-to-Velocity handshake;
until the server verifies that credential, admission remains Level 1 `VERIFIED`.

## Trust map

```text
offline release root private key
  -> signs bounded LauncherTrustStatement
     -> authorizes short-lived release public keys and revokes old keys
        -> release private key signs canonical LauncherManifest
           -> Launcher pins root public key, verifies, stages, and installs files
```

Private keys stay outside distributed clients and CI artifacts. The Launcher
contains only the pinned root public key. Manifest signatures use
`mcace-launcher-manifest-v1`; root trust signatures use
`mcace-launcher-trust-v1`. Cross-protocol signature substitution therefore fails.

## Manifest contract

A signed manifest binds schema and monotonically increasing release sequence;
product, release, build, Minecraft, loader, and minimum Launcher versions;
issued/expiry times (maximum seven days); signer key ID; and a strictly
path-sorted file list with safe relative path, exact size, SHA-256,
credential-free HTTPS URI, and executable intent.

There may be at most 8192 files and each file is capped at 4 GiB. Absolute paths,
Windows separators/drive prefixes, traversal, duplicate paths, noncanonical
ordering, URL credentials, queries, fragments, and redirects are rejected.

The root trust statement is limited to 45 days, 16 active release keys, and 512
revoked IDs. A delegated manifest must stay within the selected release key's
authorization window and use the same product ID.

## Rollback and clock behavior

`LauncherManifestCache` atomically persists the complete signed document, its
digest, and acceptance time. It rejects a lower release or trust sequence;
different manifest/trust bytes at the same sequence; a revoked, unknown,
expired, or not-yet-valid release key; a manifest requiring a newer running
Launcher; and a local clock more than five minutes behind the last checkpoint.

Deleting or patching this local state is possible for the machine owner. It is a
tamper-evident client guardrail, not the final trust boundary. Server-side launch
credential freshness and replay state are the next Phase 4 milestone.

## Atomic installation and recovery

The installer uses fixed paths under one non-symlink installation root:

```text
current
.mcace-staging
.mcace-backup
.mcace-update
```

Every file is streamed into a new staging tree, bounded by signed size, hashed,
and forced to storage. After all files verify, the installer writes and forces a
transaction journal, atomically moves `current` to backup, atomically activates
staging, records activation, then removes backup and journal. It refuses a
filesystem without same-volume atomic moves.

Startup recovery is conservative: a crash after backing up restores the old
installation; a recorded activated state retains the new installation and cleans
the backup. Hash failure before switching deletes staging and leaves `current`
untouched. Symlinks are not followed during cleanup.

## CLI verification

```powershell
.\gradlew.bat :mcace-launcher:installDist
mcace-launcher verify signed-manifest.pb root-public-x509.der launcher-cache.pb
```

Signing is intentionally a library/operator action and requires a private key
supplied outside the repository. Do not put signing keys in Gradle properties,
command-line history, the manifest, or Launcher resources.

## Verification

```powershell
.\gradlew.bat :mcace-launcher:test :mcace-protocol:test --rerun-tasks --no-daemon
```

Tests cover signature tampering, expiry, path traversal, release/trust rollback,
same-sequence equivocation, revoked old-key reuse, clock rollback, minimum
Launcher version enforcement, successful replacement, hash-failure preservation,
and crash recovery after the backup move.
