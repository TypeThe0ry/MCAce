# Behavior anti-cheat integrations

MCAce's Paper adapters consume anti-cheat flags as **observations**, not verdicts.
They never cancel an anti-cheat event, change admission, kick, ban, or invoke a
punishment command. Cloud remains the authority for policy weights and returns
`enforcement_action=NONE` for every risk ingestion request.

## Signal flow and false-positive controls

1. The Grim or Vulcan adapter normalizes only player UUID, provider/version,
   check identity, violation level, experimental status, and server timestamp.
   Raw packet data, coordinates, IP addresses, and verbose debug text are not
   collected.
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
HTTP, threshold and cooldown behavior, bounded state, and independent-provider
corroboration. A licensed Vulcan runtime smoke remains an operator release gate
because its API artifact cannot be redistributed with MCAce.
