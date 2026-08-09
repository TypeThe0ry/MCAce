package com.ellan.mcace.bungeecord;

import com.ellan.mcace.core.policy.SignedPolicyProvider;
import com.ellan.mcace.protocol.generated.IntegrityScopeRule;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.SecurityPolicy;
import com.ellan.mcace.protocol.generated.SignedPolicyDocument;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.protocol.policy.PolicyDocuments;
import com.ellan.mcace.protocol.policy.PolicyException;
import com.google.protobuf.ByteString;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

/** Issues a short-lived root-signed Fabric-first policy; all evaluation remains in MCAce core. */
final class BungeeSignedPolicyProvider implements SignedPolicyProvider {
    private static final Duration LIFETIME = Duration.ofHours(24);
    private static final Duration RENEW_BEFORE = Duration.ofHours(1);

    private final BungeeBridgeConfiguration configuration;
    private final KeyPair identity;
    private final Clock clock;
    private long sequence;
    private SignedPolicyDocument current;

    BungeeSignedPolicyProvider(BungeeBridgeConfiguration configuration, KeyPair identity, Clock clock) {
        this.configuration = Objects.requireNonNull(configuration, "configuration");
        this.identity = Objects.requireNonNull(identity, "identity");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    @Override
    public synchronized SignedPolicyDocument current() throws PolicyException {
        long now = clock.millis();
        if (current != null && current.getPolicy().size() > 0) {
            try {
                SecurityPolicy policy = SecurityPolicy.parseFrom(current.getPolicy());
                if (policy.getExpiresAtEpochMs() > now + RENEW_BEFORE.toMillis()) {
                    return current;
                }
            } catch (com.google.protobuf.InvalidProtocolBufferException exception) {
                throw new PolicyException("stored MCAce Bungee policy is malformed", exception);
            }
        }
        sequence = Math.incrementExact(sequence);
        SecurityPolicy policy = SecurityPolicy.newBuilder()
                .setPolicyVersion("bungeecord-fabric-v1")
                .setSequence(sequence)
                .setServerId(configuration.serverId())
                .setIssuedAtEpochMs(now)
                .setExpiresAtEpochMs(Math.addExact(now, LIFETIME.toMillis()))
                .setRequiredLevel(TrustLevel.VERIFIED)
                .addAllowedMinecraftVersions(configuration.minecraftVersion())
                .addAllowedLoaders(LoaderType.FABRIC)
                .addAllowedBuildIds(configuration.clientBuildId())
                .setSignerKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(identity.getPublic())))
                .addIntegrityScopes(directory("mods", true, "mods", 4096, 512L * 1024 * 1024,
                        List.of(".jar", ".disabled")))
                .addIntegrityScopes(directory("resourcepacks", false, "resourcepacks", 4096,
                        1024L * 1024 * 1024, List.of(".zip", ".jar", ".json", ".png", ".mcmeta")))
                .addIntegrityScopes(directory("shaderpacks", false, "shaderpacks", 4096,
                        1024L * 1024 * 1024, List.of(".zip", ".jar", ".json", ".properties", ".txt", ".glsl",
                                ".vsh", ".fsh")))
                .addIntegrityScopes(IntegrityScopeRule.newBuilder()
                        .setScope("config").setRequired(false).setMaxEntries(1)
                        .setMaxFileBytes(16L * 1024 * 1024).addAllowedExtensions(".txt")
                        .addExplicitRelativeFiles("options.txt"))
                .build();
        current = PolicyDocuments.sign(policy, identity.getPrivate(), identity.getPublic());
        return current;
    }

    private static IntegrityScopeRule directory(
            String scope, boolean required, String root, int maxEntries, long maxBytes, List<String> extensions) {
        return IntegrityScopeRule.newBuilder().setScope(scope).setRequired(required).setRelativeRoot(root)
                .setMaxEntries(maxEntries).setMaxFileBytes(maxBytes).addAllAllowedExtensions(extensions).build();
    }
}
