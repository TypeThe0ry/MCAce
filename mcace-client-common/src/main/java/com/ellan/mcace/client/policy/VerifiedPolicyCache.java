package com.ellan.mcace.client.policy;

import com.ellan.mcace.protocol.generated.SecurityPolicy;
import com.ellan.mcace.protocol.generated.SignedPolicyDocument;
import com.ellan.mcace.protocol.policy.PolicyDocuments;
import com.ellan.mcace.protocol.policy.PolicyException;
import com.ellan.mcace.protocol.policy.PolicyVerification;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.Clock;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;

public final class VerifiedPolicyCache {
    private static final int MAX_DOCUMENT_BYTES = 1024 * 1024;

    private final Path directory;
    private final Clock clock;

    public VerifiedPolicyCache(Path directory, Clock clock) {
        this.directory = Objects.requireNonNull(directory, "directory").toAbsolutePath().normalize();
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    public synchronized VerifiedPolicy accept(
            String serverAddress,
            SignedPolicyDocument document,
            PublicKey pinnedKey) throws IOException, PolicyException {
        Objects.requireNonNull(serverAddress, "serverAddress");
        Objects.requireNonNull(document, "document");
        Objects.requireNonNull(pinnedKey, "pinnedKey");
        if (document.getSerializedSize() > MAX_DOCUMENT_BYTES) {
            throw new PolicyException("policy document exceeds cache limit");
        }
        PolicyVerification verification = PolicyDocuments.verifyDetailed(
                document, pinnedKey, clock, Duration.ofSeconds(30));
        SecurityPolicy policy = verification.policy();
        Path path = cachePath(serverAddress);
        Optional<VerifiedPolicy> existing = loadPath(path, pinnedKey, false);
        if (existing.isPresent()) {
            SecurityPolicy cached = existing.orElseThrow().policy();
            if (!cached.getServerId().equals(policy.getServerId())) {
                throw new PolicyException("policy server identity changed for pinned address");
            }
            if (policy.getSequence() < cached.getSequence()) {
                throw new PolicyException("policy rollback detected");
            }
            if (verification.delegated() && existing.orElseThrow().delegated()) {
                if (verification.trustSequence() < existing.orElseThrow().trustSequence()) {
                    throw new PolicyException("policy trust statement rollback detected");
                }
                if (verification.trustSequence() == existing.orElseThrow().trustSequence()
                        && !MessageDigest.isEqual(
                                trustDigest(document), trustDigest(existing.orElseThrow().document()))) {
                    throw new PolicyException("policy trust statement equivocation detected");
                }
            }
            if (policy.getSequence() == cached.getSequence()
                    && !MessageDigest.isEqual(
                            existing.orElseThrow().policySha256(),
                            PolicyDocuments.policyDigest(document))) {
                throw new PolicyException("policy equivocation detected at the same sequence");
            }
        }
        Files.createDirectories(directory);
        atomicWrite(path, document.toByteArray());
        return verified(verification, document);
    }

    public synchronized Optional<VerifiedPolicy> load(String serverAddress, PublicKey pinnedKey)
            throws IOException, PolicyException {
        return loadPath(cachePath(serverAddress), pinnedKey, true);
    }

    private Optional<VerifiedPolicy> loadPath(Path path, PublicKey pinnedKey, boolean requireCurrent)
            throws IOException, PolicyException {
        if (!Files.exists(path)) {
            return Optional.empty();
        }
        byte[] encoded = Files.readAllBytes(path);
        if (encoded.length > MAX_DOCUMENT_BYTES) {
            throw new PolicyException("cached policy exceeds size limit");
        }
        SignedPolicyDocument document;
        try {
            document = SignedPolicyDocument.parseFrom(encoded);
        } catch (InvalidProtocolBufferException exception) {
            throw new PolicyException("cached policy is malformed", exception);
        }
        PolicyVerification verification = requireCurrent
                ? PolicyDocuments.verifyDetailed(document, pinnedKey, clock, Duration.ofSeconds(30))
                : PolicyDocuments.verifySignatureAndStructureDetailed(document, pinnedKey);
        return Optional.of(verified(verification, document));
    }

    private Path cachePath(String serverAddress) throws PolicyException {
        String normalized = serverAddress.trim().toLowerCase(Locale.ROOT);
        if (normalized.isBlank()) {
            throw new PolicyException("server address must not be blank");
        }
        return directory.resolve(HexFormat.of().formatHex(sha256(normalized.getBytes(StandardCharsets.UTF_8))) + ".policy");
    }

    private static VerifiedPolicy verified(PolicyVerification verification, SignedPolicyDocument document)
            throws PolicyException {
        return new VerifiedPolicy(
                verification.policy(),
                document,
                PolicyDocuments.policyDigest(document),
                verification.trustSequence(),
                verification.delegated());
    }

    private static byte[] trustDigest(SignedPolicyDocument document) throws PolicyException {
        return sha256(document.hasTrustStatement()
                ? document.getTrustStatement().toByteArray()
                : new byte[0]);
    }

    private static void atomicWrite(Path target, byte[] content) throws IOException {
        Path temporary = Files.createTempFile(target.getParent(), target.getFileName().toString(), ".tmp");
        try {
            Files.write(temporary, content);
            try {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException exception) {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temporary);
        }
    }

    private static byte[] sha256(byte[] content) throws PolicyException {
        try {
            return MessageDigest.getInstance("SHA-256").digest(content);
        } catch (NoSuchAlgorithmException exception) {
            throw new PolicyException("SHA-256 is unavailable", exception);
        }
    }
}
