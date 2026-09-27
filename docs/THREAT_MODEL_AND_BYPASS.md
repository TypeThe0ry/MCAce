# MCAce threat model and bypass boundary

This document defines what MCAce can prove, what a player can change locally,
and which evidence is allowed to cause a current-connection action.

## Security objective

MCAce gives a server a bounded view of a consenting Fabric client and combines
that view with independent server evidence. The useful claim is:

> the server received a session-bound report describing the client runtime,
> and the report can be correlated with server-side behavior.

The client report is not a proof that the JVM, JAR, renderer, operating system,
or other processes are honest. A Minecraft player controls the client files,
JVM arguments, launcher process, network endpoint, and local memory.

## What the protocol proves

The released protocol uses Ed25519 signatures, random nonces, a session ID,
timestamps, strictly increasing sequences, policy and manifest roots, and a
replay guard. These controls protect message integrity, session binding, and
replay resistance.

The client creates an ephemeral signing key for the connection and advertises
the public key in `ClientHello`. The server then verifies later frames with
that key. This proves possession of the session key. It does not prove that the
key is held by an unmodified MCAce binary. A patched client or protocol emulator
can create its own key and sign a false report.

SHA-256 is used for file and manifest integrity. CRC32C is a transport checksum.
Ed25519 provides signatures. An unreviewed custom hash does not improve this
trust boundary: a public algorithm can be reimplemented, and a secret embedded
in a client can be extracted or intercepted.

## Player-controlled bypasses

| Attack | Feasibility | Expected MCAce result |
| --- | --- | --- |
| Remove MCAce | High | `ABSENT` or limited admission when the server requires the capability |
| Patch the collector or report builder | High | A valid signature over a false `CLIENT_REPORTED` claim |
| Implement the wire protocol independently | Medium to high | A valid session report without official-code proof |
| Enable a cheat after authentication | High | Detection depends on dynamic freshness and server behavior |
| Rename or rebuild an Xray pack | High | Exact ID/hash rules miss the new artifact; behavior may still correlate |
| Use a Java agent, native hook, renderer overlay, or external process | High | Invisible to the ModList collector; only server behavior can help |
| Replay an old frame | Low | Rejected by nonce, timestamp, session, and sequence checks |
| Mimic legitimate movement or mining | Medium to high | Depends on the independent behavior provider |

The easiest forgery is a clean report signed by the attacker's own session key.
Breaking SHA-256 is unnecessary. The server must therefore keep every client
origin claim at `CLIENT_REPORTED / LOW` until an independent provider or an
identified administrator supplies stronger authority.

## Trust and action rules

The connection state should be interpreted as follows:

| State | Source | Allowed impact |
| --- | --- | --- |
| `ABSENT`/`UNTRUSTED` | Missing, invalid, or unsupported client channel | Limited admission or connection refusal |
| `CLIENT_REPORTED` | ModList, resource-pack, shader, or file observations | Observe, notice, warn, or challenge |
| `STALE` | No fresh report or heartbeat in the configured window | Freshness notice or configured temporary limitation |
| `SERVER_CORRELATED` | Client report plus same-session server signal | Feature limitation or review queue |
| `SERVER_CONFIRMED` | Authenticated independent server provider | Current-connection quarantine or deny |
| `ADMIN_REVIEWED` | Recorded operator decision and exact evidence | Current-connection action with audit and rollback |

Client silence must not create a new cheat verdict. It should expire the
freshness lease and remove access that requires a fresh client view. The current
heartbeat implementation already has `ACTIVE`, `STALE`, and `MISSING` health,
replay checks, and an opt-in consecutive-missing temporary-control policy.

## Hardening plan

1. Keep heartbeat freshness bound to the authenticated session. A valid frame
   refreshes the lease; an invalid, replayed, or stale frame does not.
2. Treat `STALE` as an operational state. Do not let an old inventory snapshot
   continue to satisfy a policy that requires current telemetry.
3. Keep exact Mod ID, file hash, content-root, and behavior rules on the server
   side where possible. The client should receive collection scope and policy
   identity, not the entire detection catalogue.
4. Require an independent Paper/Folia, Grim, Vulcan, or equivalent provider
   event before `LIMIT`, `QUARANTINE`, or `DENY` can execute from a client
   artifact observation.
5. Add adversarial fixtures for a self-generated key, a clean forged graph,
   replay, post-auth silence, and renamed resource packs. The expected result
   for a forged clean report is successful wire authentication with no
   `SERVER_CONFIRMED` event.
6. Treat a signed Launcher token as an optional future trust layer. A user-mode
   launcher raises the cost of casual emulation but is not platform attestation.
   TPM or OS attestation is a separate product and compatibility decision.

## Source and obfuscation policy

Source visibility is a product and audit choice. Publishing the protocol,
collection boundaries, threat model, and test vectors improves operator trust.
Keeping server rule catalogues and signing keys private can increase the cost of
adaptive cheating. Neither choice proves a player is honest once a JAR is on the
player's machine.

Selective client obfuscation is acceptable for IP protection and to slow casual
patching. Keep Fabric entrypoints, Mixin metadata, protocol fields, build IDs,
and diagnostics stable. Never embed server private keys or a security-critical
shared secret in the client. Obfuscation is not a release gate for the current
MCAce trust model.

## Evidence boundary

The executable live fixture proves the client/server correlation path and its
clean control. It does not execute third-party cheat code, inspect arbitrary OS
processes, or establish public-server precision and recall. A screenshot can
illustrate a client state; it cannot independently prove that Xray or an
external cheat was running.
