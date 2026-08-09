package com.ellan.mcace.core.federation;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.PublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.EnumSet;

/**
 * Immutable, strict, offline federation configuration.
 *
 * <p>Loading validates the complete document before returning. Callers may therefore atomically
 * replace an active configuration reference without exposing a partially parsed peer set.</p>
 */
public record FederationConfiguration(
        boolean enabled,
        String localNetworkId,
        Duration assertionLifetime,
        Map<String, FederationPeerPin> peers) {
    public static final String FILE_NAME = "federation.properties";
    public static final int MAX_PEERS = 64;
    private static final long MAX_CONFIGURATION_BYTES = 64L * 1024L;
    private static final String DEFAULT_CONTENT = """
            # MCAce client-carried federation is disabled by default.
            # Enabling it never opens a socket or changes local admission/risk/disposition.
            schema.version=1
            enabled=false
            local.network-id=mcace-local
            assertion.ttl.seconds=120
            peer.ids=
            # For every peer id add both fields below. The SHA-256 pin must match the X.509 key.
            # peer.example.public-key-x509-base64=
            # peer.example.key-id-sha256=
            # peer.example.capabilities=ISSUE_TO
            """;

    public FederationConfiguration {
        FederationPeerPin.requireNetworkId(localNetworkId);
        Objects.requireNonNull(assertionLifetime, "assertionLifetime");
        long lifetimeMillis;
        try {
            lifetimeMillis = assertionLifetime.toMillis();
        } catch (ArithmeticException exception) {
            throw new IllegalArgumentException("federation assertion lifetime overflow", exception);
        }
        if (assertionLifetime.isZero() || assertionLifetime.isNegative() || lifetimeMillis <= 0L
                || assertionLifetime.compareTo(ProtocolConstants.MAX_FEDERATION_ASSERTION_TTL) > 0) {
            throw new IllegalArgumentException("federation assertion lifetime is outside protocol limits");
        }
        Objects.requireNonNull(peers, "peers");
        if (peers.size() > MAX_PEERS) {
            throw new IllegalArgumentException("too many federation peer pins");
        }
        Map<String, FederationPeerPin> copy = new LinkedHashMap<>();
        for (Map.Entry<String, FederationPeerPin> entry : peers.entrySet()) {
            FederationPeerPin pin = Objects.requireNonNull(entry.getValue(), "peer pin");
            if (!entry.getKey().equals(pin.networkId()) || localNetworkId.equals(pin.networkId())
                    || copy.put(pin.networkId(), pin) != null) {
                throw new IllegalArgumentException("invalid or duplicate federation peer pin");
            }
        }
        peers = Map.copyOf(copy);
        if (enabled && peers.isEmpty()) {
            throw new IllegalArgumentException("enabled federation requires at least one peer pin");
        }
    }

    public static FederationConfiguration disabled(String localNetworkId) {
        return new FederationConfiguration(false, localNetworkId, Duration.ofMinutes(2), Map.of());
    }

    public FederationPeerPin requirePeer(String networkId, FederationPeerCapability capability) {
        FederationPeerPin pin = peers.get(Objects.requireNonNull(networkId, "networkId"));
        if (pin == null || !pin.allows(capability)) {
            throw new IllegalArgumentException("federation peer is not pinned for " + capability + ": " + networkId);
        }
        return pin;
    }

    public static FederationConfiguration loadOrCreate(Path path) throws IOException {
        Path normalized = normalizedConfigurationPath(path);
        Files.createDirectories(normalized.getParent());
        if (!Files.exists(normalized, LinkOption.NOFOLLOW_LINKS)) {
            try {
                Files.writeString(normalized, DEFAULT_CONTENT, StandardCharsets.UTF_8,
                        StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            } catch (FileAlreadyExistsException ignored) {
                // A concurrent operator/distributor supplied the document. Parse that exact file.
            }
        }
        return parse(readBoundedRegularFile(normalized));
    }

    public static FederationConfiguration parse(String content) throws IOException {
        Objects.requireNonNull(content, "content");
        if (content.getBytes(StandardCharsets.UTF_8).length > MAX_CONFIGURATION_BYTES) {
            throw new IOException("federation configuration exceeds its byte budget");
        }
        Map<String, String> values = strictProperties(content);
        Set<String> expected = new HashSet<>(Set.of(
                "schema.version", "enabled", "local.network-id", "assertion.ttl.seconds", "peer.ids"));
        if (!"1".equals(values.getOrDefault("schema.version", ""))) {
            throw new IOException("unsupported federation configuration schema.version");
        }
        boolean enabled = parseBoolean(required(values, "enabled"), "enabled");
        String localNetworkId = required(values, "local.network-id");
        long ttlSeconds = parseLong(required(values, "assertion.ttl.seconds"), "assertion.ttl.seconds");
        List<String> peerIds = parsePeerIds(values.getOrDefault("peer.ids", ""));
        Map<String, FederationPeerPin> peers = new LinkedHashMap<>();
        for (String peerId : peerIds) {
            String keyProperty = "peer." + peerId + ".public-key-x509-base64";
            String pinProperty = "peer." + peerId + ".key-id-sha256";
            String capabilitiesProperty = "peer." + peerId + ".capabilities";
            expected.add(keyProperty);
            expected.add(pinProperty);
            expected.add(capabilitiesProperty);
            PublicKey publicKey;
            byte[] declaredPin;
            Set<FederationPeerCapability> capabilities;
            try {
                byte[] encoded = Base64.getDecoder().decode(required(values, keyProperty));
                if (encoded.length == 0 || encoded.length > 128) {
                    throw new IllegalArgumentException("key length");
                }
                publicKey = Ed25519Keys.decodePublic(encoded);
                declaredPin = HexFormat.of().parseHex(required(values, pinProperty));
                capabilities = parseCapabilities(required(values, capabilitiesProperty));
            } catch (IllegalArgumentException | EnvelopeException exception) {
                throw new IOException("invalid federation peer key for " + peerId, exception);
            }
            try {
                peers.put(peerId, new FederationPeerPin(peerId, publicKey, declaredPin, capabilities));
            } catch (IllegalArgumentException exception) {
                throw new IOException("invalid federation peer pin for " + peerId, exception);
            }
        }
        Set<String> unknown = new HashSet<>(values.keySet());
        unknown.removeAll(expected);
        if (!unknown.isEmpty()) {
            throw new IOException("unknown federation configuration property: " + unknown.iterator().next());
        }
        try {
            return new FederationConfiguration(enabled, localNetworkId, Duration.ofSeconds(ttlSeconds), peers);
        } catch (IllegalArgumentException | ArithmeticException exception) {
            throw new IOException("invalid federation configuration", exception);
        }
    }

    private static Path normalizedConfigurationPath(Path path) throws IOException {
        Path normalized = Objects.requireNonNull(path, "path").toAbsolutePath().normalize();
        Path parent = normalized.getParent();
        if (parent == null) {
            throw new IOException("federation configuration path has no parent");
        }
        return normalized;
    }

    private static String readBoundedRegularFile(Path path) throws IOException {
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("unsafe federation configuration path");
        }
        long before = Files.size(path);
        if (before > MAX_CONFIGURATION_BYTES) {
            throw new IOException("federation configuration exceeds its byte budget");
        }
        byte[] bytes;
        try (FileChannel channel = FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS);
             ByteArrayOutputStream output = new ByteArrayOutputStream((int) Math.min(before, 8192L))) {
            ByteBuffer buffer = ByteBuffer.allocate(8192);
            long total = 0L;
            while (true) {
                int read = channel.read(buffer);
                if (read < 0) break;
                if (read == 0) continue;
                total = Math.addExact(total, read);
                if (total > MAX_CONFIGURATION_BYTES) {
                    throw new IOException("federation configuration exceeds its byte budget");
                }
                output.write(buffer.array(), 0, read);
                buffer.clear();
            }
            long after = channel.size();
            if (total != before || after != before || after > MAX_CONFIGURATION_BYTES) {
                throw new IOException("federation configuration changed while it was read");
            }
            bytes = output.toByteArray();
        }
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
        } catch (CharacterCodingException exception) {
            throw new IOException("federation configuration is not valid UTF-8", exception);
        }
    }

    private static Map<String, String> strictProperties(String content) throws IOException {
        Map<String, String> values = new HashMap<>();
        String[] lines = content.split("\\R", -1);
        for (int index = 0; index < lines.length; index++) {
            String line = lines[index].trim();
            if (line.isEmpty() || line.startsWith("#") || line.startsWith("!")) {
                continue;
            }
            if (line.indexOf('\\') >= 0) {
                throw new IOException("property escapes/continuations are not supported at line " + (index + 1));
            }
            int separator = line.indexOf('=');
            if (separator <= 0) {
                throw new IOException("invalid federation property at line " + (index + 1));
            }
            String key = line.substring(0, separator).trim();
            String value = line.substring(separator + 1).trim();
            if (!key.matches("[A-Za-z0-9][A-Za-z0-9._:-]*") || values.putIfAbsent(key, value) != null) {
                throw new IOException("invalid or duplicate federation property at line " + (index + 1));
            }
        }
        return values;
    }

    private static List<String> parsePeerIds(String value) throws IOException {
        if (value.isBlank()) {
            return List.of();
        }
        String[] parts = value.split(",", -1);
        if (parts.length > MAX_PEERS) {
            throw new IOException("too many federation peer ids");
        }
        List<String> result = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (String part : parts) {
            String peerId = part.trim();
            try {
                FederationPeerPin.requireNetworkId(peerId);
            } catch (IllegalArgumentException exception) {
                throw new IOException("invalid federation peer id", exception);
            }
            if (!seen.add(peerId)) {
                throw new IOException("duplicate federation peer id");
            }
            result.add(peerId);
        }
        return List.copyOf(result);
    }

    private static Set<FederationPeerCapability> parseCapabilities(String value) throws IOException {
        String[] parts = value.split(",", -1);
        EnumSet<FederationPeerCapability> capabilities = EnumSet.noneOf(FederationPeerCapability.class);
        for (String part : parts) {
            try {
                if (!capabilities.add(FederationPeerCapability.valueOf(part.trim()))) {
                    throw new IOException("duplicate federation peer capability");
                }
            } catch (IllegalArgumentException exception) {
                throw new IOException("invalid federation peer capability", exception);
            }
        }
        if (capabilities.isEmpty()) {
            throw new IOException("federation peer capabilities must not be empty");
        }
        return Set.copyOf(capabilities);
    }

    private static boolean parseBoolean(String value, String name) throws IOException {
        if ("true".equalsIgnoreCase(value)) return true;
        if ("false".equalsIgnoreCase(value)) return false;
        throw new IOException("invalid federation " + name);
    }

    private static long parseLong(String value, String name) throws IOException {
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException exception) {
            throw new IOException("invalid federation " + name, exception);
        }
    }

    private static String required(Map<String, String> values, String key) throws IOException {
        String value = values.get(key);
        if (value == null || value.isBlank()) {
            throw new IOException("missing federation configuration property: " + key);
        }
        return value;
    }
}
