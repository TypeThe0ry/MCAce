package com.ellan.mcace.core.authority;

import com.ellan.mcace.protocol.ProtocolConstants;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Canonical operator profile that gives an authority-profile digest concrete meaning.
 * Every security-relevant static provider field is included in the digest.
 */
public final class BackendAuthorityProfile {
    private static final Duration MAXIMUM_COOLDOWN = Duration.ofDays(30);
    private final String sha256;
    private final Map<String, ProviderContract> providers;
    private final int requiredIndependentDomains;
    private final Duration maximumProviderWindow;
    private final Duration cooldown;

    public BackendAuthorityProfile(
            List<ProviderContract> providers,
            int requiredIndependentDomains,
            Duration maximumProviderWindow,
            Duration cooldown) {
        Objects.requireNonNull(providers, "providers");
        if (providers.size() < 2
                || providers.size() > ProtocolConstants.MAX_BACKEND_AUTHORITY_PROVIDERS) {
            throw new IllegalArgumentException("authority profile provider count is outside bounds");
        }
        LinkedHashMap<String, ProviderContract> byId = new LinkedHashMap<>();
        Set<String> domains = new HashSet<>();
        for (ProviderContract provider : providers) {
            Objects.requireNonNull(provider, "provider");
            if (byId.put(provider.providerId(), provider) != null) {
                throw new IllegalArgumentException("authority profile contains a duplicate provider ID");
            }
            domains.add(provider.trustDomainId());
        }
        if (requiredIndependentDomains < 2 || requiredIndependentDomains > domains.size()) {
            throw new IllegalArgumentException("invalid independent trust-domain quorum");
        }
        this.maximumProviderWindow = boundedDuration(
                maximumProviderWindow,
                ProtocolConstants.MAX_BACKEND_AUTHORITY_OBSERVATION_AGE,
                false,
                "maximumProviderWindow");
        this.cooldown = boundedDuration(cooldown, MAXIMUM_COOLDOWN, true, "cooldown");
        this.providers = Map.copyOf(byId);
        this.requiredIndependentDomains = requiredIndependentDomains;
        this.sha256 = digest();
    }

    public String sha256() { return sha256; }
    public int requiredIndependentDomains() { return requiredIndependentDomains; }
    public Duration maximumProviderWindow() { return maximumProviderWindow; }
    public Duration cooldown() { return cooldown; }
    public Set<String> providerIds() { return providers.keySet(); }
    public Optional<ProviderContract> provider(String providerId) {
        return Optional.ofNullable(providers.get(providerId));
    }

    private String digest() {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("JDK SHA-256 is unavailable", exception);
        }
        field(digest, "mcace/backend-authority/profile/v1");
        number(digest, requiredIndependentDomains);
        number(digest, maximumProviderWindow.toMillis());
        number(digest, cooldown.toMillis());
        ArrayList<ProviderContract> ordered = new ArrayList<>(providers.values());
        ordered.sort(java.util.Comparator.comparing(ProviderContract::providerId));
        number(digest, ordered.size());
        for (ProviderContract provider : ordered) {
            field(digest, provider.providerId());
            field(digest, provider.trustDomainId());
            field(digest, provider.providerVersion());
            field(digest, provider.stableCheckFamily());
            number(digest, provider.threshold());
        }
        return java.util.HexFormat.of().formatHex(digest.digest());
    }

    private static Duration boundedDuration(
            Duration value, Duration maximum, boolean allowZero, String field) {
        Objects.requireNonNull(value, field);
        if (value.isNegative() || (!allowZero && value.isZero())
                || value.compareTo(maximum) > 0
                || !Duration.ofMillis(value.toMillis()).equals(value)) {
            throw new IllegalArgumentException(field + " is outside authority profile bounds");
        }
        return value;
    }

    private static void field(MessageDigest digest, String value) {
        byte[] encoded = value.getBytes(StandardCharsets.US_ASCII);
        digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(encoded.length).array());
        digest.update(encoded);
    }

    private static void number(MessageDigest digest, long value) {
        digest.update(ByteBuffer.allocate(Long.BYTES).putLong(value).array());
    }

    public record ProviderContract(
            String trustDomainId,
            String providerId,
            String providerVersion,
            String stableCheckFamily,
            int threshold) {
        public ProviderContract {
            trustDomainId = BackendAuthorityPin.bounded(trustDomainId, "trustDomainId");
            providerId = BackendAuthorityPin.bounded(providerId, "providerId");
            providerVersion = BackendAuthorityPin.bounded(providerVersion, "providerVersion");
            stableCheckFamily = BackendAuthorityPin.bounded(
                    stableCheckFamily, "stableCheckFamily");
            if (threshold <= 0) {
                throw new IllegalArgumentException("provider threshold must be positive");
            }
        }
    }
}
