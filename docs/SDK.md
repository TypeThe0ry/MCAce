# MCAce third-party SDK 1.0

The public SDK is a read-only integration boundary. It exposes immutable trust,
admission, risk, session, and content-free evidence summaries. It cannot change
admission, execute a disposition, request a screenshot, read raw evidence, or
obtain a storage path or key. Client-reported values remain review signals and
must not be the sole reason for an irreversible punishment.

## Dependency and discovery

Compile against `mcace-sdk` using `compileOnly` (or the equivalent provided
scope). MCAce's Paper/Folia, Velocity, and BungeeCord jars each contain their own
SDK copy, so consumers must not cast the plugin instance to their independently
loaded `MCAceApi` class. Instead:

1. Declare MCAce as an optional or required plugin dependency using the target
   platform's normal descriptor.
2. Obtain the MCAce plugin instance from Bukkit/Paper, Velocity, or BungeeCord's
   plugin manager.
3. Call `MCAceInterop.discover(pluginInstance)`.
4. Negotiate API version `1.0` and the capabilities the integration actually
   needs. Missing, malformed, or incompatible state is unavailable—not verified.

```java
Object mcacePlugin = /* platform plugin-manager lookup */;
MCAceInteropBridge bridge = MCAceInterop.discover(mcacePlugin)
        .orElseThrow(() -> new IllegalStateException("MCAce SDK bridge unavailable"));

MCAceSdkNegotiationResult result = bridge.negotiate(
        new MCAceSdkNegotiationRequest(
                new MCAceSdkVersion(1, 0),
                Set.of(MCAceCapability.PLAYER_SECURITY_SNAPSHOT)));
if (!result.compatible()) {
    // Keep the integration inactive; never infer VERIFIED from an unavailable bridge.
    return;
}

bridge.snapshot(playerId).ifPresent(snapshot -> {
    // Read-only review or gameplay eligibility logic owned by this server plugin.
});
```

The provider method is `mcaceInteropV1()` and returns
`Function<Map<String,Object>,Map<String,Object>>`. Only JDK bootstrap types cross
the plugin class-loader boundary. The consumer SDK validates map depth, entry
counts, text lengths, enum tokens, timestamps, and value types before producing
consumer-local immutable records.

## Capabilities

- `PLAYER_SECURITY_SNAPSHOT`, `TRUST_SUMMARY`, and `RISK_SUMMARY` are the baseline.
- `SESSION_SUMMARY` is optional and contains non-sensitive lifecycle metadata.
- `EVIDENCE_SUMMARY` is optional and contains at most 64 metadata records. It has
  no bytes, hashes, file names, paths, storage locations, keys, review URLs, or
  disposition recommendations. `clientReported` is explicit.

Unknown capabilities or a different major API version fail negotiation. Minor
versions may add optional capabilities without changing the version-one bridge.

## Platform notes

- Paper/Folia still registers the direct `MCAceApi` Bukkit service for integrations
  sharing MCAce's class identity, but the interop bridge is the portable path.
- Velocity and BungeeCord integrations locate the MCAce plugin instance and use
  the same bridge.
- Calls must happen after MCAce has enabled and before it disables. Disconnect or
  missing snapshots return unavailable state.

`SdkCompatibilityContractTest` verifies the actual shadow jars, isolated class
identities, version negotiation, bridge round trips, immutable results, and
rejection of sensitive or malformed payload types.
