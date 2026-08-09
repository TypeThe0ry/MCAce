package com.ellan.mcace.client.integrity;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

public record ClientIntegrityBundle(List<ScopeIntegrityManifest> scopes, byte[] aggregateRootSha256) {
    private static final byte[] DOMAIN = "mcace-integrity-bundle-v1\0".getBytes(StandardCharsets.US_ASCII);

    public ClientIntegrityBundle {
        Objects.requireNonNull(scopes, "scopes");
        scopes = scopes.stream().sorted(Comparator.comparing(ScopeIntegrityManifest::scope)).toList();
        Set<String> names = new HashSet<>();
        if (scopes.isEmpty() || scopes.stream().anyMatch(scope -> !names.add(scope.scope()))) {
            throw new IllegalArgumentException("integrity bundle requires unique scopes");
        }
        Objects.requireNonNull(aggregateRootSha256, "aggregateRootSha256");
        if (aggregateRootSha256.length != 32) {
            throw new IllegalArgumentException("aggregate root must contain 32 bytes");
        }
        aggregateRootSha256 = aggregateRootSha256.clone();
    }

    @Override
    public byte[] aggregateRootSha256() {
        return aggregateRootSha256.clone();
    }

    public Optional<ScopeIntegrityManifest> scope(String name) {
        return scopes.stream().filter(scope -> scope.scope().equals(name)).findFirst();
    }

    public static ClientIntegrityBundle of(List<ScopeIntegrityManifest> scopes) throws IntegrityScanException {
        try {
            List<ScopeIntegrityManifest> sorted = scopes.stream()
                    .sorted(Comparator.comparing(ScopeIntegrityManifest::scope))
                    .toList();
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(DOMAIN);
            for (ScopeIntegrityManifest scope : sorted) {
                byte[] name = scope.scope().getBytes(StandardCharsets.UTF_8);
                digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(name.length).array());
                digest.update(name);
                digest.update((byte) (scope.present() ? 1 : 0));
                digest.update(scope.rootSha256());
            }
            return new ClientIntegrityBundle(sorted, digest.digest());
        } catch (NoSuchAlgorithmException exception) {
            throw new IntegrityScanException("SHA-256 is unavailable", exception);
        }
    }
}
