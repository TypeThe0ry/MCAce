# Opt-in backend interaction guard

The pending-admission review found that UNKNOWN/VERIFYING is not verified trust,
but the observational backend does not prevent ordinary interaction by itself.
The new `admission-guard.enabled` option provides an explicit backend-local
restriction. Its default is false, preserving existing MONITOR installations.

Enable in Paper/Folia MCAce `config.yml` before starting the test server:

```yaml
admission-guard:
  enabled: true
```

Only the admission receiver's signature-verified observer can install a permit.
Both admission status and trust must be VERIFIED. The permit binds the exact
Player connection object, not only UUID, and carries the signed snapshot expiry.
Each action checks freshness directly, without relying on the periodic expiry
task. Non-verified updates, expiry, quit/join and plugin shutdown revoke permits.
Wrong-carrier and already-expired updates do not enable access.

The listener cancels block breaking/placing, ordinary block/item and entity
interaction, item dropping/pickup, inventory clicks/drags, player/projectile
attacks and player commands while a permit is missing. The exact `/mcace` and
`/mcace:mcace` command names remain available for the existing read-only check
command; this does not override command permissions.

This is not a complete quarantine system: it does not freeze movement, hide
chunks, block chat, audit every special event or constrain other trusted server
plugins. It is not proof of Xray/executable-cheat detection. Do not increase the
handshake deadline on the assumption that this feature is full isolation.
There are no bans, account changes, inventory mutations or permission grants.
Disable the option and restart the plugin/server to restore observational behavior.

Validation status is recorded below; no real-server acceptance is implied by
unit event-construction tests.

## Validation, 2026-09-08

- Base commit: `8ba9044ec09e8b21777075110302857c71825267` plus this change.
- Controller JDK 21, cached offline Gradle, one worker.
- Initial Paper suite: 86 discovered, 1 failed, 8 skipped. The new command
  event test used a constructor requiring a live Bukkit server. It was changed
  to supply the recipient set explicitly; no product behavior was weakened.
- Corrected `BackendInteractionGuardTest`: 4 tests, 0 failures, 0 errors,
  0 skipped; Gradle exit 0 (53 seconds).
- Combined focused regression: guard 4, `PaperAdmissionReceiverTest` 5,
  `BackendLocalSessionActionAdapterTest` 3; all 12 passed with no errors or
  skips. `:mcace-server-paper:shadowJar` also succeeded in that run (42 seconds).
  This is a development build, not a new exact-source release bundle.
- This focused rerun is not a clean rerun of the entire Paper suite. Skipped
  environment/license checks remain unverified, and real Paper/Folia event
  dispatch and signed client-to-backend interaction acceptance remain pending.
- Existing release-bundle artifacts predate this product change and must not
  be represented as containing it.
