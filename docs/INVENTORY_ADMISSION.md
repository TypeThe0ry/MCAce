# Opt-in inventory admission (development)

This is an administrator's entry rule, not a claim that MCAce has independently
confirmed cheating. The implementation currently targets Velocity only. It is
not a kernel/process scanner, an Xray classifier, or a permanent ban feature.

## Configuration

Create `inventory-admission.properties` in the MCAce Velocity plugin data directory:

```properties
enabled=false
denied-mod-ids=example_prohibited_mod
denied-selected-resource-packs=file/example-prohibited-pack.zip
```

These are examples, not a shipped cheat signature list. Replace them with the
exact loaded Mod IDs and selected resource-pack identifiers prohibited by your
server. Set `enabled=true` only when ready to reject matching connections, then
restart through the normal maintenance procedure. Do not use plugin hot reload.
Absent files or an absent enabled key leave the feature disabled. Disable it and
restart to roll back. No real server configuration is changed by this commit.

**This opt-in is independent of `enforcement.mode=MONITOR`.** That setting controls
the existing signed disposition path; it does not override this separately enabled
inventory admission rule. Existing trusted-source limits remain unchanged.

Matching is exact and case-sensitive. Lists are comma-separated, trimmed, unique,
at most 256 entries, each at most 256 characters with no control characters.
Empty lists are permitted. Trailing empty entries, duplicates, oversized values
and invalid booleans are configuration errors. The file is capped at 128 KiB.

Only loaded Mod IDs and selected resource-pack IDs are compared. An installed but
unloaded Mod or an unselected pack does not match. Missing telemetry is not a clean
verdict; use the separate client requirement for missing-client admission. Renamed
or hidden reports can evade identifier rules. These rules do not validate pack
content or detect unknown cheating programs; content-based detection remains a
separate capability.

## Execution and evidence

Initial and accepted dynamic manifests use the existing bounded audit handoff.
A matching finding carries only its reason and server receipt identity into the
Velocity scheduler. The physical-login lock is acquired before the coordinator
monitor. Session, sequence, receive time and age (three normal report intervals,
currently 900 seconds) are checked inside the same coordinator critical section
as the nonblocking disconnect API call. Report acceptance/removal cannot interleave
with that call. This does not wait for network completion.

There is one dispatch attempt per coordinator session. A failure or ambiguous
exception consumes that attempt to avoid repeated actions; it is logged as failed,
not successful. Successful/ambiguous attempts also stop pending route requests for
the physical login. Reconnection gets a new session and is evaluated again.
No risk score or SERVER_CONFIRMED authority is manufactured.

Logs contain `authority=ADMIN_CONFIGURED_INVENTORY`, a content-free finding and
result. `DISPATCHED` means `DISCONNECT_API_ACCEPTED`, with
`client-receipt-confirmed=false`. This is not a durable punishment receipt. Confirm
actual disconnection with live server/client evidence before claiming efficacy.

Queue saturation, audit evaluation failure or scheduler failure can prevent an
attempt. The current path is therefore not a guaranteed pre-backend admission
barrier. The client may enter before asynchronous rejection, and later pack
changes may wait up to the existing five-minute reporting cadence plus processing.
No low-latency or fail-closed entry guarantee is claimed.

## Remaining acceptance

Verify a real enabled client with normal inventory, each prohibited input, removal
and reconnect, reporting delay, replaced report, and actual disconnect result.
Test all supported Minecraft versions and proxy parity before broad release
claims. Unit tests and successful compilation do not satisfy this live gate.
