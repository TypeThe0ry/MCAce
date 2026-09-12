# Client self-protection / 客户端自保护

MCAce v0.0.1 keeps self-protection in a transparent user-mode boundary. It
does not install a hidden service, launcher, agent, kernel driver, or persistent
capture component.

## Release JAR identity

Both Fabric client lines (`1.21.11` and modern `26.1.2`/`26.2`) expose a
release marker containing the build ID and the SHA-256 of the local CodeSource
JAR. When `mcace.platform.smoke.expected-artifact-sha256` is configured, the
platform smoke path calls `verifiedCodeSourceSha256` and fails closed if the
loaded entrypoint JAR differs from the expected final remap artifact. The
loaded marker is also bound into the signed client hello metadata.

This detects accidental replacement, stale development classes, and an
incorrect remap artifact; it is not a claim that a hostile client is
unforgeable. Server policy still treats every client-origin observation as
advisory until an independent provider corroborates it.

## Operational checks

1. Build the final remap JAR.
2. Calculate its SHA-256 with `Get-FileHash`.
3. Configure the exact value for the platform smoke check.
4. Confirm the startup marker contains the same `code_source_sha256`.
5. Retain the marker and build ID beside the exact commit evidence.

The release gate remains explicit: a self-integrity mismatch blocks the client
smoke check, while a missing expected hash is reported as an unconfigured
check rather than silently upgraded to trusted.
