package com.ellan.mcace.cloud.auth;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

public final class FileServerIdentityRegistry implements ServerIdentityRegistry {
    private final Map<String, ServerIdentity> identities;

    private FileServerIdentityRegistry(Map<String, ServerIdentity> identities) {
        this.identities = Map.copyOf(identities);
    }

    public static FileServerIdentityRegistry load(Path path) throws IOException {
        Map<String, ServerIdentity> identities = new LinkedHashMap<>();
        int lineNumber = 0;
        for (String rawLine : Files.readAllLines(path, StandardCharsets.UTF_8)) {
            lineNumber++;
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            String[] fields = line.split("\\|", -1);
            if (fields.length != 3) throw invalid(lineNumber, "expected server_id|public_key|scopes");
            String serverId;
            try {
                serverId = ServerIdentity.validateServerId(fields[0].trim());
            } catch (IllegalArgumentException exception) {
                throw invalid(lineNumber, exception.getMessage(), exception);
            }
            if (identities.containsKey(serverId)) throw invalid(lineNumber, "duplicate server identity");
            byte[] encodedKey;
            try {
                encodedKey = Base64.getDecoder().decode(fields[1].trim());
            } catch (IllegalArgumentException exception) {
                throw invalid(lineNumber, "invalid Base64 public key", exception);
            }
            Set<ApiScope> scopes = EnumSet.noneOf(ApiScope.class);
            for (String value : fields[2].split(",")) {
                try {
                    scopes.add(ApiScope.valueOf(value.trim()));
                } catch (IllegalArgumentException exception) {
                    throw invalid(lineNumber, "invalid API scope", exception);
                }
            }
            try {
                identities.put(serverId, new ServerIdentity(
                        serverId, Ed25519Keys.decodePublic(encodedKey), scopes));
            } catch (EnvelopeException | IllegalArgumentException exception) {
                throw invalid(lineNumber, "invalid Ed25519 server identity", exception);
            }
        }
        if (identities.isEmpty()) throw new IOException("server identity registry is empty");
        return new FileServerIdentityRegistry(identities);
    }

    public static ServerIdentityRegistry of(ServerIdentity identity) {
        return serverId -> identity.serverId().equals(serverId) ? Optional.of(identity) : Optional.empty();
    }

    @Override
    public Optional<ServerIdentity> find(String serverId) {
        return Optional.ofNullable(identities.get(serverId));
    }

    private static IOException invalid(int lineNumber, String message) {
        return new IOException("invalid server registry line " + lineNumber + ": " + message);
    }

    private static IOException invalid(int lineNumber, String message, Exception cause) {
        return new IOException("invalid server registry line " + lineNumber + ": " + message, cause);
    }
}
