package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.disposition.DispositionPolicyCompiler;
import com.ellan.mcace.core.disposition.DispositionPolicyConfigurationCompiler;
import com.ellan.mcace.core.disposition.DispositionCatalogPreview;
import com.ellan.mcace.protocol.generated.DetectionRule;
import com.ellan.mcace.protocol.generated.DispositionPolicyConfiguration;
import com.ellan.mcace.protocol.generated.DispositionPolicyDocument;
import com.ellan.mcace.protocol.generated.SignedDispositionPolicyDocument;
import com.ellan.mcace.protocol.policy.DispositionPolicyDocuments;
import com.ellan.mcace.protocol.policy.PolicyDocuments;
import com.ellan.mcace.protocol.policy.PolicyException;
import com.google.protobuf.ByteString;
import com.google.protobuf.TextFormat;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.KeyPair;
import java.time.Clock;
import java.time.Duration;
import java.util.Comparator;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;

/**
 * Strict, local administrator publisher for signed disposition policies.
 *
 * <p>Textproto configuration deliberately cannot specify signing fields, sequence/predecessor,
 * policy identity, or absolute timestamps. All of those values are derived while holding the same
 * path lock as the runtime source. Invalid input therefore cannot replace a known-good policy.
 */
public final class FileDispositionPolicyPublisher {
    public static final int MAX_CONFIGURATION_BYTES = 256 * 1024;
    private static final int MAX_HISTORY_ENTRIES = 128;
    private static final int BUFFER_BYTES = 8_192;
    private static final Duration MAX_VALIDITY = Duration.ofDays(30);

    private final FileSignedDispositionPolicySource source;
    private final Path policyPath;
    private final Clock clock;
    private final KeyPair rootKeyPair;

    public FileDispositionPolicyPublisher(Path policyPath, Clock clock, KeyPair rootKeyPair)
            throws PolicyException {
        this.source = new FileSignedDispositionPolicySource(policyPath, clock, rootKeyPair);
        this.policyPath = source.path();
        this.clock = Objects.requireNonNull(clock, "clock");
        this.rootKeyPair = Objects.requireNonNull(rootKeyPair, "rootKeyPair");
    }

    /** Parses and validates an administrator textproto before replacing the signed policy. */
    public PublishedDispositionPolicy publish(Path configurationPath) throws PolicyException {
        DispositionPolicyConfiguration configuration = parseConfiguration(configurationPath);
        synchronized (FileSignedDispositionPolicySource.pathLock(policyPath)) {
            SignedDispositionPolicyDocument currentSigned = source.current();
            DispositionPolicyDocument current = DispositionPolicyDocuments.verifySignatureAndStructure(
                    currentSigned, rootKeyPair.getPublic());
            DispositionPolicyDocument next = buildNext(current, configuration);
            SignedDispositionPolicyDocument signed = DispositionPolicyDocuments.sign(
                    next, rootKeyPair.getPrivate(), rootKeyPair.getPublic());
            byte[] bytes = signed.toByteArray();
            if (bytes.length > source.maxDocumentBytes()) {
                throw new PolicyException("published disposition policy exceeds storage budget");
            }
            byte[] hash = DispositionPolicyDocuments.documentSha256(next);
            // Archive the currently active, verified bytes before replacement.  If this fails the
            // current policy remains untouched; an unpublished candidate is never retained.
            writeHistoryBeforeReplace(current.getSequence(),
                    DispositionPolicyDocuments.documentSha256(current), currentSigned.toByteArray());
            replaceCurrentAtomically(bytes);
            // The current policy is committed at this point. History retention is audit help, not
            // an admission gate, so post-commit retention failure cannot report a false failure.
            try {
                writeHistoryBeforeReplace(next.getSequence(), hash, bytes);
                pruneHistory();
            } catch (PolicyException ignored) {
                // Operators still have the previous history entry and the now-active signed file.
            }
            return new PublishedDispositionPolicy(next.getVersion(), next.getSequence(), hash, next.getRulesCount());
        }
    }

    /**
     * Validates and compiles administrator input without signing, writing, bootstrapping, or
     * exposing policy content. Warning values are stable codes only.
     */
    public DispositionCatalogPreview preview(Path configurationPath) throws PolicyException {
        DispositionPolicyConfiguration configuration = parseConfiguration(configurationPath);
        try {
            return DispositionPolicyConfigurationCompiler.compile(configuration).preview();
        } catch (RuntimeException exception) {
            throw new PolicyException("disposition policy preview rejected", exception);
        }
    }

    /** Safe copy-paste starter configuration. It has no rule, private-key, signature, or time fields. */
    public static String safeDefaultConfiguration() {
        return "schema_version: 1\nversion: \"admin-observe-1\"\nrollout_stage: \"OBSERVE\"\nvalidity_seconds: 86400\n";
    }

    /** Safe catalog example: no real hash, URL, or enabled selection. */
    public static String safeCatalogExampleConfiguration() {
        return "schema_version: 1\n"
                + "version: \"catalog-example-1\"\n"
                + "rollout_stage: \"OBSERVE\"\n"
                + "validity_seconds: 86400\n"
                + "catalog_entries {\n"
                + "  entry_id: \"example-accessibility\"\n"
                + "  category: ACCESSIBILITY\n"
                + "  selector { artifact_type: DETECTION_ARTIFACT_MOD "
                + "match_type: DETECTION_MATCH_ADMIN_CLASSIFICATION artifact_id: \"example\" }\n"
                + "  confidence: DETECTION_CONFIDENCE_LOW\n"
                + "  suggested_action: DISPOSITION_OBSERVE\n"
                + "  player_message_key: \"mcace.catalog.example\"\n"
                + "  operator_reason: \"Example only; not selected by default.\"\n"
                + "  false_positive_notes: \"Example entry is intentionally not selected.\"\n"
                + "  source_id: \"example\"\n"
                + "  source_summary: \"Local safe example without an external source.\"\n"
                + "  default_enabled: false\n"
                + "}\n";
    }

    private DispositionPolicyConfiguration parseConfiguration(Path configurationPath) throws PolicyException {
        Path path = requireAbsoluteNormalizedPath(configurationPath, "configurationPath");
        byte[] bytes = readBoundedRegularFile(path, MAX_CONFIGURATION_BYTES, "configuration");
        DispositionPolicyConfiguration.Builder builder = DispositionPolicyConfiguration.newBuilder();
        try {
            String text = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString();
            TextFormat.Parser.newBuilder()
                    .setAllowUnknownFields(false)
                    .setAllowUnknownExtensions(false)
                    .setSingularOverwritePolicy(TextFormat.Parser.SingularOverwritePolicy.FORBID_SINGULAR_OVERWRITES)
                    .build().merge(text, builder);
        } catch (TextFormat.ParseException | CharacterCodingException exception) {
            throw new PolicyException("invalid disposition policy textproto: " + path, exception);
        }
        DispositionPolicyConfiguration configuration = builder.build();
        validateConfiguration(configuration);
        return configuration;
    }

    private static void validateConfiguration(DispositionPolicyConfiguration configuration) throws PolicyException {
        if (configuration.getSchemaVersion() != 1 || configuration.getVersion().isBlank()
                || configuration.getRolloutStage().isBlank() || configuration.getValiditySeconds() == 0
                || configuration.getValiditySeconds() > MAX_VALIDITY.toSeconds()) {
            throw new PolicyException("invalid disposition policy configuration identity or validity");
        }
        try {
            DispositionPolicyConfigurationCompiler.compile(configuration);
        } catch (RuntimeException exception) {
            throw new PolicyException("invalid disposition policy configuration", exception);
        }
    }

    private DispositionPolicyDocument buildNext(
            DispositionPolicyDocument current, DispositionPolicyConfiguration configuration) throws PolicyException {
        long now = clock.millis();
        long expires;
        try {
            expires = Math.addExact(now, Math.multiplyExact((long) configuration.getValiditySeconds(), 1_000L));
        } catch (ArithmeticException exception) {
            throw new PolicyException("policy configuration validity overflows clock", exception);
        }
        byte[] predecessor = DispositionPolicyDocuments.documentSha256(current);
        long sequence;
        try {
            sequence = Math.addExact(current.getSequence(), 1L);
        } catch (ArithmeticException exception) {
            throw new PolicyException("policy sequence overflow", exception);
        }
        DispositionPolicyDocument.Builder builder = DispositionPolicyDocument.newBuilder()
                .setSchemaVersion(1)
                .setPolicyId(current.getPolicyId())
                .setVersion(configuration.getVersion())
                .setSequence(sequence)
                .setIssuedAtEpochMs(now)
                .setEffectiveFromEpochMs(now)
                .setExpiresAtEpochMs(expires)
                .setRolloutStage(configuration.getRolloutStage())
                .setSignerKeyIdSha256(ByteString.copyFrom(PolicyDocuments.keyId(rootKeyPair.getPublic())))
                .setPreviousDocumentSha256(ByteString.copyFrom(predecessor));
        DispositionPolicyConfigurationCompiler.CompiledDispositionConfiguration compiled;
        try {
            compiled = DispositionPolicyConfigurationCompiler.compile(configuration);
        } catch (RuntimeException exception) {
            throw new PolicyException("published disposition policy cannot be compiled safely", exception);
        }
        for (com.ellan.mcace.core.disposition.DispositionCatalogSourceSummary summary
                : compiled.preview().sourceSummaries()) {
            try {
                new com.ellan.mcace.core.disposition.CatalogSourceProvenance(
                        summary.sourceUri(), summary.sourceRevision(), summary.sourceManifestPath(),
                        summary.retrievedAtEpochMs()).validateRetrievedNotAfter(now);
            } catch (IllegalArgumentException exception) {
                throw new PolicyException("published catalog source provenance is unsafe", exception);
            }
        }
        for (DetectionRule rule : compiled.rules()) {
            try {
                com.ellan.mcace.core.disposition.CatalogSourceProvenance.from(rule)
                        .validateRetrievedNotAfter(now);
            } catch (IllegalArgumentException exception) {
                throw new PolicyException("published catalog source provenance is unsafe", exception);
            }
            builder.addRules(rule.toBuilder()
                    .setIntroducedAtEpochMs(now).setEffectiveFromEpochMs(now).setExpiresAtEpochMs(expires));
        }
        DispositionPolicyDocument document = builder.build();
        // This enforces selector/action/scope safety, including no name-only DENY, no unknown enum,
        // no foundation ALLOW, and exact-player-only ALLOW exceptions.
        DispositionPolicyDocuments.validateStructure(document);
        try {
            DispositionPolicyCompiler.compileVerified(document);
        } catch (RuntimeException exception) {
            throw new PolicyException("published disposition policy cannot be compiled safely", exception);
        }
        return document;
    }

    private void writeHistoryBeforeReplace(long sequence, byte[] hash, byte[] bytes) throws PolicyException {
        Path history = policyPath.getParent().resolve("history");
        try {
            Files.createDirectories(history);
            BasicFileAttributes attributes = Files.readAttributes(
                    history, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (attributes.isSymbolicLink() || !attributes.isDirectory()) {
                throw new PolicyException("invalid disposition policy history directory");
            }
        } catch (IOException exception) {
            throw new PolicyException("cannot create disposition policy history directory", exception);
        }
        Path target = history.resolve(String.format(Locale.ROOT, "%020d", sequence)
                + "-" + java.util.HexFormat.of().formatHex(hash) + ".pb");
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) return;
        writeAtomically(target, bytes, false);
    }

    private void replaceCurrentAtomically(byte[] bytes) throws PolicyException {
        writeAtomically(policyPath, bytes, true);
    }

    private static void writeAtomically(Path target, byte[] bytes, boolean replace) throws PolicyException {
        Path parent = target.getParent();
        Path temporary = null;
        try {
            temporary = Files.createTempFile(parent, "." + target.getFileName() + ".", ".tmp");
            try (FileChannel channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                ByteBuffer buffer = ByteBuffer.wrap(bytes);
                while (buffer.hasRemaining()) {
                    if (channel.write(buffer) == 0) throw new IOException("failed to write policy file");
                }
                channel.force(true);
            }
            try {
                if (replace) Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
                else Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException exception) {
                if (replace) Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
                else Files.move(temporary, target);
            }
        } catch (IOException exception) {
            throw new PolicyException("cannot atomically write disposition policy file: " + target, exception);
        } finally {
            if (temporary != null) try { Files.deleteIfExists(temporary); } catch (IOException ignored) { }
        }
    }

    private void pruneHistory() throws PolicyException {
        Path history = policyPath.getParent().resolve("history");
        try (var files = Files.list(history)) {
            var entries = files.filter(path -> Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
                    .sorted(Comparator.comparing(Path::getFileName)).toList();
            for (int index = 0; index < entries.size() - MAX_HISTORY_ENTRIES; index++) Files.delete(entries.get(index));
        } catch (IOException exception) {
            throw new PolicyException("cannot prune disposition policy history", exception);
        }
    }

    private static Path requireAbsoluteNormalizedPath(Path path, String name) {
        Objects.requireNonNull(path, name);
        if (!path.isAbsolute() || !path.equals(path.normalize()) || path.getFileName() == null) {
            throw new IllegalArgumentException(name + " must be an absolute normalized file path");
        }
        return path;
    }

    private static byte[] readBoundedRegularFile(Path path, int maximum, String label) throws PolicyException {
        try {
            BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
            if (attributes.isSymbolicLink() || !attributes.isRegularFile() || attributes.size() > maximum) {
                throw new PolicyException("invalid or oversized " + label + " file: " + path);
            }
            try (SeekableByteChannel channel = Files.newByteChannel(path, Set.of(StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS));
                    ByteArrayOutputStream output = new ByteArrayOutputStream((int) attributes.size())) {
                ByteBuffer buffer = ByteBuffer.allocate(BUFFER_BYTES);
                int total = 0;
                while (channel.read(buffer) != -1) {
                    int read = buffer.position();
                    if (read == 0) continue;
                    if (read > maximum - total) throw new PolicyException(label + " exceeds " + maximum + " bytes");
                    output.write(buffer.array(), 0, read);
                    total += read;
                    buffer.clear();
                }
                return output.toByteArray();
            }
        } catch (IOException exception) {
            throw new PolicyException("cannot read " + label + " file: " + path, exception);
        }
    }
}
