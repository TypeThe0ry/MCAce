package com.ellan.mcace.paper;

import com.ellan.mcace.core.authority.BackendAuthorityPin;
import com.ellan.mcace.core.authority.BackendAuthorityProfile;
import com.ellan.mcace.core.authority.AuthorityFilePreflight;
import com.ellan.mcace.core.authority.ServerAuthorityJournalPreflight;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Signature;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.bukkit.configuration.ConfigurationSection;
import org.bukkit.configuration.file.FileConfiguration;

/** Strict Paper/Folia signer, provider-profile and durable-journal configuration. */
record PaperServerAuthorityConfiguration(
        boolean enabled,
        String proxyInstanceId,
        String backendInstanceId,
        KeyPair backendIdentity,
        String backendKeyIdSha256,
        Path issuanceJournal,
        long journalQuotaBytes,
        Duration observationLifetime,
        BackendAuthorityProfile profile) {

    private static final int MAXIMUM_PRIVATE_KEY_FILE_BYTES = 4096;
    private static final int MAXIMUM_PUBLIC_KEY_FILE_BYTES = 4096;
    private static final int MAXIMUM_PAPER_CONFIGURATION_BYTES = 256 * 1024;

    private static final Set<String> ROOT_KEYS = Set.of(
            "enabled", "mode", "proxy-instance-id", "backend-instance-id",
            "backend-private-key-path", "backend-public-key-path", "backend-key-id-sha256",
            "issuance-journal-path", "journal-quota-bytes", "observation-ttl-ms", "profile");
    private static final Set<String> PROFILE_KEYS = Set.of(
            "sha256", "required-independent-domains", "maximum-provider-window-ms",
            "cooldown-ms", "providers");
    private static final Set<String> PROVIDER_KEYS = Set.of(
            "trust-domain-id", "version", "stable-check-family", "threshold");

    PaperServerAuthorityConfiguration {
        Objects.requireNonNull(proxyInstanceId, "proxyInstanceId");
        Objects.requireNonNull(backendInstanceId, "backendInstanceId");
        Objects.requireNonNull(backendIdentity, "backendIdentity");
        Objects.requireNonNull(backendKeyIdSha256, "backendKeyIdSha256");
        Objects.requireNonNull(issuanceJournal, "issuanceJournal");
        Objects.requireNonNull(observationLifetime, "observationLifetime");
        Objects.requireNonNull(profile, "profile");
    }

    static PaperServerAuthorityConfiguration load(FileConfiguration config, Path dataDirectory)
            throws IOException {
        Objects.requireNonNull(config, "config");
        Path root = Objects.requireNonNull(dataDirectory, "dataDirectory")
                .toAbsolutePath().normalize();
        AuthorityFilePreflight.createDirectoriesWithoutLinks(root);
        preflightRawConfiguration(root);
        ConfigurationSection section = config.getConfigurationSection("authority");
        if (section == null || !strictBoolean(section, "enabled", false)) {
            String mode = section == null ? "MONITOR"
                    : section.getString("mode", "MONITOR").strip().toUpperCase(Locale.ROOT);
            if (!"MONITOR".equals(mode)) {
                throw new IOException("authority.mode must be MONITOR in phase 1");
            }
            return null;
        }
        Path rawConfiguration = root.resolve("config.yml");
        if (Files.exists(rawConfiguration, LinkOption.NOFOLLOW_LINKS)) {
            AuthorityFilePreflight.requirePrivateRegularFile(
                    root, rawConfiguration, "Paper authority configuration");
        }
        try {
            requireOnly(section, ROOT_KEYS, "authority");
            String mode = required(section, "mode").toUpperCase(Locale.ROOT);
            if (!"MONITOR".equals(mode)) {
                throw new IllegalArgumentException("authority.mode must be MONITOR in phase 1");
            }
            String proxyInstanceId = required(section, "proxy-instance-id");
            String backendInstanceId = required(section, "backend-instance-id");
            Path privatePath = AuthorityFilePreflight.resolveRelative(
                    root, required(section, "backend-private-key-path"),
                    "authority backend private key path");
            Path publicPath = AuthorityFilePreflight.resolveRelative(
                    root, required(section, "backend-public-key-path"),
                    "authority backend public key path");
            KeyPair identity = readKeyPair(root, privatePath, publicPath);
            String keyId = required(section, "backend-key-id-sha256");
            if (!BackendAuthorityPin.keyIdFor(identity.getPublic()).equals(keyId)) {
                throw new IllegalArgumentException("configured backend key ID does not match the key pair");
            }
            Path journal = AuthorityFilePreflight.resolveRelative(
                    root, required(section, "issuance-journal-path"),
                    "authority issuance journal path");
            AuthorityFilePreflight.requirePrivateRegularFile(
                    root, journal, "authority issuance journal");
            long quota = positiveLong(section, "journal-quota-bytes");
            if (quota > ServerAuthorityJournalPreflight.maximumQuotaBytes()) {
                throw new IllegalArgumentException("authority journal quota exceeds the supported maximum");
            }
            Duration observationLifetime = Duration.ofMillis(
                    positiveLong(section, "observation-ttl-ms"));
            if (observationLifetime.compareTo(ProtocolConstants.MAX_BACKEND_AUTHORITY_TTL) > 0) {
                throw new IllegalArgumentException("authority observation TTL exceeds the protocol maximum");
            }

            ConfigurationSection profileSection = requiredSection(section, "profile");
            requireOnly(profileSection, PROFILE_KEYS, "authority.profile");
            ConfigurationSection providersSection = requiredSection(profileSection, "providers");
            List<String> providerIds = providersSection.getKeys(false).stream().sorted().toList();
            if (providerIds.size() < 2
                    || providerIds.size() > ProtocolConstants.MAX_BACKEND_AUTHORITY_PROVIDERS) {
                throw new IllegalArgumentException("authority profile requires 2-8 providers");
            }
            List<BackendAuthorityProfile.ProviderContract> providers = new ArrayList<>();
            for (String providerId : providerIds) {
                ConfigurationSection provider = requiredSection(providersSection, providerId);
                requireOnly(provider, PROVIDER_KEYS,
                        "authority.profile.providers." + providerId);
                providers.add(new BackendAuthorityProfile.ProviderContract(
                        required(provider, "trust-domain-id"), providerId,
                        required(provider, "version"), required(provider, "stable-check-family"),
                        positiveInt(provider, "threshold")));
            }
            BackendAuthorityProfile profile = new BackendAuthorityProfile(
                    providers,
                    positiveInt(profileSection, "required-independent-domains"),
                    Duration.ofMillis(positiveLong(profileSection, "maximum-provider-window-ms")),
                    Duration.ofMillis(nonNegativeLong(profileSection, "cooldown-ms")));
            if (!profile.sha256().equals(required(profileSection, "sha256"))) {
                throw new IllegalArgumentException("configured authority profile SHA-256 is stale or invalid");
            }
            return new PaperServerAuthorityConfiguration(
                    true, proxyInstanceId, backendInstanceId, identity, keyId,
                    journal, quota, observationLifetime, profile);
        } catch (EnvelopeException | GeneralSecurityException | IllegalArgumentException exception) {
            throw new IOException("invalid Paper backend authority configuration", exception);
        }
    }

    private static KeyPair readKeyPair(Path root, Path privatePath, Path publicPath)
            throws IOException, EnvelopeException, GeneralSecurityException {
        byte[] privateBytes = AuthorityFilePreflight.readBoundedPrivateRegularFile(
                root, privatePath, MAXIMUM_PRIVATE_KEY_FILE_BYTES,
                "authority backend private key");
        try {
            byte[] publicFile = AuthorityFilePreflight.readBoundedPrivateRegularFile(
                    root, publicPath, MAXIMUM_PUBLIC_KEY_FILE_BYTES,
                    "authority backend public key");
            String publicText = new String(publicFile, StandardCharsets.US_ASCII).strip();
            if (privateBytes.length == 0 || publicText.isEmpty()) {
                throw new IOException("authority backend key file is outside bounds");
            }
            byte[] publicBytes;
            try {
                publicBytes = Base64.getDecoder().decode(publicText);
            } catch (IllegalArgumentException exception) {
                throw new IOException("authority backend public key is not valid Base64", exception);
            }
            KeyPair keyPair = new KeyPair(
                    Ed25519Keys.decodePublic(publicBytes),
                    Ed25519Keys.decodePrivate(privateBytes));
            byte[] probe = "mcace/paper-authority/key-pair-check/v1"
                    .getBytes(StandardCharsets.US_ASCII);
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(keyPair.getPrivate());
            signature.update(probe);
            byte[] signed = signature.sign();
            signature.initVerify(keyPair.getPublic());
            signature.update(probe);
            if (!signature.verify(signed)) {
                throw new IllegalArgumentException("authority backend key pair does not match");
            }
            return keyPair;
        } finally {
            Arrays.fill(privateBytes, (byte) 0);
        }
    }

    private static void preflightRawConfiguration(Path root) throws IOException {
        Path configuration = root.resolve("config.yml");
        if (!Files.exists(configuration, LinkOption.NOFOLLOW_LINKS)) {
            // Unit callers may provide an in-memory FileConfiguration. Production always has a file.
            return;
        }
        byte[] raw = AuthorityFilePreflight.readBoundedRegularFile(
                root, configuration, MAXIMUM_PAPER_CONFIGURATION_BYTES,
                "Paper authority configuration");
        final String yaml;
        try {
            String decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(raw)).toString();
            yaml = decoded.startsWith("\uFEFF") ? decoded.substring(1) : decoded;
        } catch (CharacterCodingException exception) {
            throw new IOException("Paper authority configuration is not valid UTF-8", exception);
        }
        rejectDuplicateRawAuthorityKeys(yaml);
    }

    /**
     * Bukkit's parsed configuration has already collapsed duplicate YAML mappings. Scan the
     * security-sensitive subtree before trusting it and permit only simple block-mapping keys.
     */
    private static void rejectDuplicateRawAuthorityKeys(String yaml) throws IOException {
        Map<List<String>, Set<String>> keysByParent = new HashMap<>();
        List<RawYamlNode> stack = new ArrayList<>();
        boolean insideAuthority = false;
        int authorityIndent = -1;
        int authorityBlocks = 0;
        String[] lines = yaml.split("\\r?\\n", -1);
        int rootIndentation = rawRootIndentation(lines);
        for (int lineNumber = 1; lineNumber <= lines.length; lineNumber++) {
            String line = lines[lineNumber - 1];
            if (line.isBlank() || line.stripLeading().startsWith("#")) {
                continue;
            }
            int indentation = leadingSpaces(line);
            if (indentation < 0) {
                if (insideAuthority) {
                    throw rawYamlError(lineNumber,
                            "tabs are not permitted in the authority subtree");
                }
                continue;
            }
            if (insideAuthority && indentation <= authorityIndent) {
                insideAuthority = false;
                stack.clear();
            }
            String content = line.substring(indentation);
            RawYamlMapping mapping = parseRawMapping(content, insideAuthority, lineNumber);

            if (indentation == rootIndentation && mapping != null
                    && "authority".equals(mapping.key())) {
                if (++authorityBlocks > 1) {
                    throw rawYamlError(lineNumber, "duplicate root authority mapping");
                }
                if (!mapping.valueWithoutComment().isEmpty()) {
                    throw rawYamlError(lineNumber,
                            "authority must use a block mapping, not an inline value");
                }
                insideAuthority = true;
                authorityIndent = indentation;
                stack.clear();
                stack.add(new RawYamlNode(indentation, "authority"));
                continue;
            }

            if (!insideAuthority) {
                continue;
            }
            if (mapping == null) {
                throw rawYamlError(lineNumber,
                        "authority permits only simple block-mapping entries");
            }
            while (!stack.isEmpty()
                    && stack.get(stack.size() - 1).indentation() >= indentation) {
                stack.remove(stack.size() - 1);
            }
            if (stack.isEmpty()) {
                throw rawYamlError(lineNumber, "authority indentation is inconsistent");
            }
            List<String> parent = stack.stream().map(RawYamlNode::key).toList();
            Set<String> keys = keysByParent.computeIfAbsent(parent, ignored -> new HashSet<>());
            if (!keys.add(mapping.key())) {
                throw rawYamlError(lineNumber,
                        "duplicate authority mapping key " + mapping.key());
            }
            stack.add(new RawYamlNode(indentation, mapping.key()));
        }
    }

    private static int rawRootIndentation(String[] lines) throws IOException {
        int minimum = Integer.MAX_VALUE;
        for (int lineNumber = 1; lineNumber <= lines.length; lineNumber++) {
            String line = lines[lineNumber - 1];
            if (line.isBlank() || line.stripLeading().startsWith("#")) {
                continue;
            }
            int indentation = leadingSpaces(line);
            if (indentation >= 0
                    && parseRawMapping(line.substring(indentation), false, lineNumber) != null) {
                minimum = Math.min(minimum, indentation);
            }
        }
        return minimum == Integer.MAX_VALUE ? 0 : minimum;
    }

    private static int leadingSpaces(String line) {
        int index = 0;
        while (index < line.length() && line.charAt(index) == ' ') {
            index++;
        }
        return index < line.length() && line.charAt(index) == '\t' ? -1 : index;
    }

    private static RawYamlMapping parseRawMapping(
            String content, boolean strict, int lineNumber) throws IOException {
        boolean singleQuoted = false;
        boolean doubleQuoted = false;
        boolean escaped = false;
        int colon = -1;
        for (int index = 0; index < content.length(); index++) {
            char character = content.charAt(index);
            if (doubleQuoted && character == '\\' && !escaped) {
                escaped = true;
                continue;
            }
            if (character == '\'' && !doubleQuoted) {
                singleQuoted = !singleQuoted;
            } else if (character == '"' && !singleQuoted && !escaped) {
                doubleQuoted = !doubleQuoted;
            } else if (character == ':' && !singleQuoted && !doubleQuoted) {
                colon = index;
                break;
            }
            escaped = false;
        }
        if (colon < 0) {
            if (strict) {
                throw rawYamlError(lineNumber, "authority mapping entry has no colon");
            }
            return null;
        }
        String key = canonicalRawKey(content.substring(0, colon).strip(), strict, lineNumber);
        if (key == null) {
            return null;
        }
        String value = content.substring(colon + 1).stripLeading();
        int comment = value.indexOf('#');
        String valueWithoutComment = (comment < 0 ? value : value.substring(0, comment)).strip();
        return new RawYamlMapping(key, valueWithoutComment);
    }

    private static String canonicalRawKey(String token, boolean strict, int lineNumber)
            throws IOException {
        if (token.length() >= 2 && token.charAt(0) == '\''
                && token.charAt(token.length() - 1) == '\'') {
            token = token.substring(1, token.length() - 1).replace("''", "'");
        } else if (token.length() >= 2 && token.charAt(0) == '"'
                && token.charAt(token.length() - 1) == '"') {
            String quoted = token.substring(1, token.length() - 1);
            if (quoted.indexOf('\\') >= 0) {
                if (strict) {
                    throw rawYamlError(lineNumber,
                            "escaped authority mapping keys are not permitted");
                }
                return null;
            }
            token = quoted;
        }
        if (!token.matches("[A-Za-z0-9_.-]+")) {
            if (strict) {
                throw rawYamlError(lineNumber,
                        "authority mapping key uses unsupported YAML syntax");
            }
            return null;
        }
        return token;
    }

    private static IOException rawYamlError(int lineNumber, String message) {
        return new IOException("invalid raw Paper authority configuration at line "
                + lineNumber + ": " + message);
    }

    private record RawYamlNode(int indentation, String key) {
    }

    private record RawYamlMapping(String key, String valueWithoutComment) {
    }

    private static boolean strictBoolean(
            ConfigurationSection section, String key, boolean defaultValue) throws IOException {
        Object raw = section.get(key);
        if (raw == null) return defaultValue;
        if (raw instanceof Boolean value) return value;
        throw new IOException("authority." + key + " must be true or false");
    }

    private static String required(ConfigurationSection section, String key) {
        Object raw = section.get(key);
        if (!(raw instanceof String value) || value.isBlank()) {
            throw new IllegalArgumentException(section.getCurrentPath() + "." + key + " is required");
        }
        return value.strip();
    }

    private static ConfigurationSection requiredSection(ConfigurationSection section, String key) {
        ConfigurationSection child = section.getConfigurationSection(key);
        if (child == null) {
            throw new IllegalArgumentException(section.getCurrentPath() + "." + key + " is required");
        }
        return child;
    }

    private static void requireOnly(
            ConfigurationSection section, Set<String> allowed, String path) {
        Set<String> unknown = new HashSet<>(section.getKeys(false));
        unknown.removeAll(allowed);
        if (!unknown.isEmpty()) {
            throw new IllegalArgumentException("unknown " + path + " keys: "
                    + unknown.stream().sorted().toList());
        }
    }

    private static long positiveLong(ConfigurationSection section, String key) {
        long value = nonNegativeLong(section, key);
        if (value == 0L) throw new IllegalArgumentException(key + " must be positive");
        return value;
    }

    private static long nonNegativeLong(ConfigurationSection section, String key) {
        Object raw = section.get(key);
        if (!(raw instanceof Number number)) {
            throw new IllegalArgumentException(key + " must be an integer");
        }
        long value = number.longValue();
        if (value < 0L || number.doubleValue() != (double) value) {
            throw new IllegalArgumentException(key + " must be a non-negative integer");
        }
        return value;
    }

    private static int positiveInt(ConfigurationSection section, String key) {
        long value = positiveLong(section, key);
        if (value > Integer.MAX_VALUE) throw new IllegalArgumentException(key + " exceeds bounds");
        return (int) value;
    }

}
