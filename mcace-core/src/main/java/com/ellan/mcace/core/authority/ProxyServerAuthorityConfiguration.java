package com.ellan.mcace.core.authority;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.PublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;

/** Strict, default-disabled proxy configuration for the signed backend-authority channel. */
public final class ProxyServerAuthorityConfiguration {
    public static final String FILE_NAME = "authority.properties";
    private static final int MAXIMUM_CONFIGURATION_BYTES = 64 * 1024;
    private static final int MAXIMUM_PUBLIC_KEY_FILE_BYTES = 4096;
    private static final String DEFAULT_CONTENT = """
            # Signed Paper/Folia SERVER_CONFIRMED authority is opt-in and MONITOR-only in phase 1.
            authority.enabled=false
            authority.mode=MONITOR
            """;

    private final boolean enabled;
    private final String proxyInstanceId;
    private final Duration grantLifetime;
    private final BackendAuthorityRegistry registry;

    private ProxyServerAuthorityConfiguration(
            boolean enabled,
            String proxyInstanceId,
            Duration grantLifetime,
            BackendAuthorityRegistry registry) {
        this.enabled = enabled;
        this.proxyInstanceId = Objects.requireNonNull(proxyInstanceId, "proxyInstanceId");
        this.grantLifetime = Objects.requireNonNull(grantLifetime, "grantLifetime");
        this.registry = Objects.requireNonNull(registry, "registry");
    }

    public static ProxyServerAuthorityConfiguration loadOrCreate(Path path) throws IOException {
        Path normalized = Objects.requireNonNull(path, "path").toAbsolutePath().normalize();
        Path parent = Objects.requireNonNull(normalized.getParent(), "configuration parent");
        AuthorityFilePreflight.createDirectoriesWithoutLinks(parent);
        if (Files.notExists(normalized, LinkOption.NOFOLLOW_LINKS)) {
            try {
                byte[] defaults = DEFAULT_CONTENT.getBytes(StandardCharsets.UTF_8);
                try (SeekableByteChannel channel = Files.newByteChannel(normalized,
                        StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE,
                        LinkOption.NOFOLLOW_LINKS)) {
                    ByteBuffer source = ByteBuffer.wrap(defaults);
                    while (source.hasRemaining()) {
                        channel.write(source);
                    }
                }
            } catch (java.nio.file.FileAlreadyExistsException ignored) {
                // Another startup won the safe-default creation race.
            }
        }
        byte[] configurationBytes = AuthorityFilePreflight.readBoundedRegularFile(
                parent, normalized, MAXIMUM_CONFIGURATION_BYTES,
                "backend authority configuration");
        Properties properties = new StrictProperties();
        try (Reader reader = new InputStreamReader(
                new ByteArrayInputStream(configurationBytes),
                StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT))) {
            try {
                properties.load(reader);
            } catch (IllegalArgumentException exception) {
                throw new IOException("invalid or duplicate authority configuration property",
                        exception);
            }
        }
        boolean enabled = strictBoolean(properties.getProperty("authority.enabled", "false"),
                "authority.enabled");
        String mode = properties.getProperty("authority.mode", "MONITOR")
                .strip().toUpperCase(Locale.ROOT);
        if (!"MONITOR".equals(mode)) {
            throw new IOException("authority.mode must be MONITOR in phase 1");
        }
        if (!enabled) {
            return new ProxyServerAuthorityConfiguration(
                    false, "disabled", Duration.ofSeconds(1), BackendAuthorityRegistry.disabled());
        }

        AuthorityFilePreflight.requirePrivateRegularFile(
                parent, normalized, "backend authority configuration");

        Set<String> consumed = new HashSet<>(Set.of("authority.enabled", "authority.mode"));
        try {
            String proxyInstanceId = required(properties, consumed, "authority.proxy-instance-id");
            long grantTtlMillis = positiveLong(
                    required(properties, consumed, "authority.grant-ttl-ms"),
                    "authority.grant-ttl-ms");
            Duration grantLifetime = Duration.ofMillis(grantTtlMillis);
            if (grantLifetime.compareTo(ProtocolConstants.MAX_BACKEND_AUTHORITY_TTL) > 0) {
                throw new IllegalArgumentException("authority grant TTL exceeds the protocol maximum");
            }
            List<String> backends = list(
                    required(properties, consumed, "authority.backends"), "authority.backends");
            Map<String, BackendAuthorityPin> pins = new LinkedHashMap<>();
            for (String backend : backends) {
                String prefix = "authority.backend." + backend + ".";
                String backendInstanceId = required(properties, consumed, prefix + "instance-id");
                Path publicKeyPath = AuthorityFilePreflight.resolveRelative(parent,
                        required(properties, consumed, prefix + "public-key-path"),
                        "authority backend public key path");
                PublicKey publicKey = readPublicKey(parent, publicKeyPath);
                String keyId = required(properties, consumed, prefix + "key-id-sha256");
                List<String> profileNames = list(
                        required(properties, consumed, prefix + "profiles"), prefix + "profiles");
                Map<String, BackendAuthorityProfile> profiles = new LinkedHashMap<>();
                for (String profileName : profileNames) {
                    String profilePrefix = prefix + "profile." + profileName + ".";
                    int quorum = positiveInt(required(properties, consumed,
                            profilePrefix + "required-independent-domains"),
                            profilePrefix + "required-independent-domains");
                    Duration maximumWindow = Duration.ofMillis(positiveLong(
                            required(properties, consumed, profilePrefix + "maximum-provider-window-ms"),
                            profilePrefix + "maximum-provider-window-ms"));
                    Duration cooldown = Duration.ofMillis(nonNegativeLong(
                            required(properties, consumed, profilePrefix + "cooldown-ms"),
                            profilePrefix + "cooldown-ms"));
                    List<String> providerIds = list(required(properties, consumed,
                            profilePrefix + "providers"), profilePrefix + "providers");
                    List<BackendAuthorityProfile.ProviderContract> providers = new ArrayList<>();
                    for (String providerId : providerIds) {
                        String providerPrefix = profilePrefix + "provider." + providerId + ".";
                        providers.add(new BackendAuthorityProfile.ProviderContract(
                                required(properties, consumed, providerPrefix + "trust-domain-id"),
                                providerId,
                                required(properties, consumed, providerPrefix + "version"),
                                required(properties, consumed, providerPrefix + "stable-check-family"),
                                positiveInt(required(properties, consumed, providerPrefix + "threshold"),
                                        providerPrefix + "threshold")));
                    }
                    BackendAuthorityProfile profile = new BackendAuthorityProfile(
                            providers, quorum, maximumWindow, cooldown);
                    String expectedDigest = required(
                            properties, consumed, profilePrefix + "sha256");
                    if (!profile.sha256().equals(expectedDigest)) {
                        throw new IllegalArgumentException(
                                "authority profile digest does not match configured profile " + profileName);
                    }
                    if (profiles.put(profile.sha256(), profile) != null) {
                        throw new IllegalArgumentException(
                                "duplicate canonical authority profile for backend " + backend);
                    }
                }
                BackendAuthorityPin pin = new BackendAuthorityPin(
                        backend, backendInstanceId, keyId, publicKey, profiles);
                if (pins.put(backend, pin) != null) {
                    throw new IllegalArgumentException("duplicate authority backend");
                }
            }
            Set<String> unknown = new HashSet<>(properties.stringPropertyNames());
            unknown.removeAll(consumed);
            if (!unknown.isEmpty()) {
                throw new IllegalArgumentException("unknown authority configuration keys: "
                        + unknown.stream().sorted().toList());
            }
            return new ProxyServerAuthorityConfiguration(
                    true, BackendAuthorityPin.bounded(proxyInstanceId, "proxyInstanceId"),
                    grantLifetime, new BackendAuthorityRegistry(pins));
        } catch (EnvelopeException | IllegalArgumentException exception) {
            throw new IOException("invalid backend authority configuration", exception);
        }
    }

    public boolean enabled() { return enabled; }
    public String proxyInstanceId() { return proxyInstanceId; }
    public Duration grantLifetime() { return grantLifetime; }
    public BackendAuthorityRegistry registry() { return registry; }

    private static String required(Properties properties, Set<String> consumed, String key) {
        consumed.add(key);
        String value = properties.getProperty(key);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("missing authority configuration key " + key);
        }
        return value.strip();
    }

    private static List<String> list(String value, String field) {
        List<String> values = java.util.Arrays.stream(value.split(",", -1))
                .map(String::strip).toList();
        if (values.isEmpty() || values.size() > ProtocolConstants.MAX_BACKEND_AUTHORITY_PROVIDERS
                || values.stream().anyMatch(String::isEmpty)
                || values.stream().distinct().count() != values.size()) {
            throw new IllegalArgumentException(field + " is outside authority bounds");
        }
        values.forEach(entry -> BackendAuthorityPin.bounded(entry, field));
        return List.copyOf(values);
    }

    private static boolean strictBoolean(String value, String field) throws IOException {
        if ("true".equalsIgnoreCase(value.strip())) return true;
        if ("false".equalsIgnoreCase(value.strip())) return false;
        throw new IOException(field + " must be true or false");
    }

    private static long positiveLong(String value, String field) {
        long parsed = nonNegativeLong(value, field);
        if (parsed == 0L) throw new IllegalArgumentException(field + " must be positive");
        return parsed;
    }

    private static long nonNegativeLong(String value, String field) {
        try {
            long parsed = Long.parseLong(value);
            if (parsed < 0L) throw new NumberFormatException("negative");
            return parsed;
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException(field + " must be a non-negative integer", exception);
        }
    }

    private static int positiveInt(String value, String field) {
        long parsed = positiveLong(value, field);
        if (parsed > Integer.MAX_VALUE) {
            throw new IllegalArgumentException(field + " exceeds integer bounds");
        }
        return (int) parsed;
    }

    private static PublicKey readPublicKey(Path root, Path path)
            throws IOException, EnvelopeException {
        byte[] keyFile = AuthorityFilePreflight.readBoundedPrivateRegularFile(
                root, path, MAXIMUM_PUBLIC_KEY_FILE_BYTES,
                "authority backend public key");
        String encoded = new String(keyFile, StandardCharsets.US_ASCII).strip();
        if (encoded.isEmpty()) {
            throw new IOException("invalid authority backend public key file");
        }
        try {
            return Ed25519Keys.decodePublic(Base64.getDecoder().decode(encoded));
        } catch (IllegalArgumentException exception) {
            throw new IOException("authority backend public key is not valid Base64", exception);
        }
    }

    private static final class StrictProperties extends Properties {
        private static final long serialVersionUID = 1L;

        @Override
        public synchronized Object put(Object key, Object value) {
            if (containsKey(key)) {
                throw new IllegalArgumentException(
                        "duplicate authority configuration key " + key);
            }
            return super.put(key, value);
        }
    }
}
