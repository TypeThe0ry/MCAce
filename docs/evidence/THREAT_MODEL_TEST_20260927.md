# Threat model regression evidence — 2026-09-27

This record covers the trust-boundary test added after the architecture review.
It is development evidence for the working tree and does not change the v0.0.1
release tag.

## Command

```powershell
.\gradlew.bat :mcace-core:test `
  --tests com.ellan.mcace.core.session.HandshakeIntegrationTest `
  --offline --no-daemon --no-parallel --max-workers=1 `
  --no-configuration-cache --console=plain
```

## Result

| Field | Value |
| --- | --- |
| Source baseline | `0bce88e` (`main`) plus the current working-tree test and documentation changes |
| Test class | `com.ellan.mcace.core.session.HandshakeIntegrationTest` |
| Test cases | `40` |
| Failures | `0` |
| Errors | `0` |
| New adversarial case | `selfGeneratedClientKeyCanAuthenticateAClaimWithoutCreatingServerAuthority()` |
| JUnit XML SHA-256 | `ba9080396ef448fe0d421a32cae0ff663959b9bca78c6a53c20624524b479ed5` |

The new case generates a fresh client key, satisfies the required loaded-Mod
graph capability, and sends a clean self-report. The server accepts the wire
session as `VERIFIED`, while the audit sink records no independent risk event.
This is the intended boundary: a client report can be authenticated as a
message without becoming `SERVER_CONFIRMED` authority.

The same class also covers replay rejection, session binding, heartbeat
`ACTIVE`/`STALE`/`MISSING` transitions, consecutive missing-heartbeat control,
post-auth observation replay, and recovery after a valid heartbeat.

## Limitations

- The test is a protocol/core integration test; it is not a public server.
- It does not execute third-party cheat code or inspect arbitrary OS processes.
- A `VERIFIED` result in this test means protocol admission, not a claim that
  the client code is unmodified or cheat-free.
- The current production authority ceiling remains `MONITOR`; high-impact
  actions still require independent server authority or administrator review.
