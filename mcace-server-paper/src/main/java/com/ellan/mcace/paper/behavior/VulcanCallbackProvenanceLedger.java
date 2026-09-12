package com.ellan.mcace.paper.behavior;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.CodeSource;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.bukkit.event.Event;
import org.bukkit.event.EventPriority;
import org.bukkit.event.HandlerList;
import org.bukkit.event.Listener;
import org.bukkit.plugin.Plugin;
import org.bukkit.plugin.RegisteredListener;

/**
 * Optional, fail-closed evidence ledger for the release-grade licensed Vulcan gate.
 *
 * <p>The ledger is disabled during ordinary server operation.  The V3 evidence runner enables it
 * with three JVM properties and consumes the append-only JSONL file after the Paper process has
 * exited.  No caller boolean is accepted as callback provenance: a record is written from the
 * registered Bukkit callback itself and binds the provider plugin, event/runtime code sources,
 * reflected accessor declarations, process incarnation, callback thread and privacy-preserving
 * commitments to the extracted semantic fields.</p>
 */
final class VulcanCallbackProvenanceLedger implements AutoCloseable {
    static final String PATH_PROPERTY = "mcace.vulcan.provenance.ledger";
    static final String ATTEMPT_PROPERTY = "mcace.vulcan.provenance.attempt";
    static final String CHALLENGE_PROPERTY = "mcace.vulcan.provenance.challenge";
    static final String SCHEMA = "MCACE_VULCAN_CALLBACK_PROVENANCE_V1";

    private static final HexFormat HEX = HexFormat.of();
    private static final String ZERO_SHA256 = "0".repeat(64);

    private final boolean enabled;
    private final Clock clock;
    private final Plugin owner;
    private final Plugin provider;
    private final Class<? extends Event> registeredEventClass;
    private final Listener listener;
    private final String captureAttemptId;
    private final String captureChallenge;
    private final long processId;
    private final String processStartedAt;
    private final String processIncarnationSha256;
    private final Path ledgerPath;
    private final Object ledgerFileKey;
    private final FileChannel channel;
    private final FileLock lock;
    private long sequence;
    private String previousRecordSha256 = ZERO_SHA256;

    private VulcanCallbackProvenanceLedger() {
        enabled = false;
        clock = Clock.systemUTC();
        owner = null;
        provider = null;
        registeredEventClass = null;
        listener = null;
        captureAttemptId = "";
        captureChallenge = "";
        processId = -1L;
        processStartedAt = "";
        processIncarnationSha256 = "";
        ledgerPath = null;
        ledgerFileKey = null;
        channel = null;
        lock = null;
    }

    private VulcanCallbackProvenanceLedger(
            Path path,
            String attempt,
            String challenge,
            Plugin owner,
            Plugin provider,
            Class<? extends Event> registeredEventClass,
            Listener listener,
            Clock clock) throws IOException {
        this.enabled = true;
        this.clock = clock;
        this.owner = owner;
        this.provider = provider;
        this.registeredEventClass = registeredEventClass;
        this.listener = listener;
        this.captureAttemptId = attempt;
        this.captureChallenge = challenge;
        ProcessHandle.Info processInfo = ProcessHandle.current().info();
        this.processId = ProcessHandle.current().pid();
        this.processStartedAt = processInfo.startInstant()
                .orElseThrow(() -> new IOException("process start instant is unavailable"))
                .toString();
        this.processIncarnationSha256 = sha256Utf8(
                "pid=" + processId + "\nstarted_at=" + processStartedAt + "\n");
        assertNewLedgerPath(path);
        this.channel = FileChannel.open(path, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        FileLock acquired = null;
        try {
            acquired = channel.tryLock();
            if (acquired == null) {
                throw new IOException("provenance ledger lock is unavailable");
            }
        } catch (Throwable failure) {
            channel.close();
            throw failure;
        }
        this.lock = acquired;
        this.ledgerPath = path;
        BasicFileAttributes attributes = readDirectFileAttributes(path);
        this.ledgerFileKey = attributes.fileKey();
        if (ledgerFileKey == null) {
            try {
                lock.release();
            } finally {
                channel.close();
            }
            throw new IOException("provenance ledger file identity is unavailable");
        }
    }

    static VulcanCallbackProvenanceLedger open(
            Plugin owner,
            Plugin provider,
            Class<? extends Event> registeredEventClass,
            Listener listener,
            Clock clock) throws ReflectiveOperationException {
        Objects.requireNonNull(owner, "owner");
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(registeredEventClass, "registeredEventClass");
        Objects.requireNonNull(listener, "listener");
        Objects.requireNonNull(clock, "clock");
        String configuredPath = System.getProperty(PATH_PROPERTY, "").strip();
        String attempt = System.getProperty(ATTEMPT_PROPERTY, "").strip().toLowerCase();
        String challenge = System.getProperty(CHALLENGE_PROPERTY, "").strip().toLowerCase();
        if (configuredPath.isEmpty()) {
            if (!attempt.isEmpty() || !challenge.isEmpty()) {
                throw new ReflectiveOperationException("partial Vulcan provenance configuration");
            }
            return new VulcanCallbackProvenanceLedger();
        }
        if (!attempt.matches("[0-9a-f]{32}") || !challenge.matches("[0-9a-f]{64}")) {
            throw new ReflectiveOperationException("invalid Vulcan provenance attempt/challenge");
        }
        try {
            return new VulcanCallbackProvenanceLedger(
                    Path.of(configuredPath).toAbsolutePath().normalize(), attempt, challenge,
                    owner, provider, registeredEventClass, listener, clock);
        } catch (IOException exception) {
            throw new ReflectiveOperationException("Vulcan provenance ledger initialization failed", exception);
        }
    }

    boolean enabled() {
        return enabled;
    }

    void assertRegisteredHandlerIdentity() throws ReflectiveOperationException {
        if (!enabled) return;
        Method handlerMethod = registeredEventClass.getMethod("getHandlerList");
        Object value = handlerMethod.invoke(null);
        if (!(value instanceof HandlerList handlers)) {
            throw new ReflectiveOperationException("Vulcan event handler list is unavailable");
        }
        int matches = 0;
        for (RegisteredListener registered : handlers.getRegisteredListeners()) {
            if (registered.getListener() == listener
                    && registered.getPlugin() == owner
                    && registered.getPriority() == EventPriority.MONITOR
                    && registered.isIgnoringCancelled()) {
                matches++;
            }
        }
        if (matches != 1) {
            throw new ReflectiveOperationException("Vulcan callback registration identity is not unique");
        }
    }

    synchronized boolean append(
            Event event,
            UUID playerId,
            String providerEventId,
            String check,
            String stableCheck,
            double violation,
            Instant observedAt,
            List<Method> accessors) {
        if (!enabled) return true;
        try {
            if (!channel.isOpen() || !lock.isValid() || sequence != channelPositionLineCount()) {
                return false;
            }
            // Re-check the Bukkit registration at callback time; a successful
            // constructor-time registration alone is not runtime provenance.
            assertRegisteredHandlerIdentity();
            assertRuntimeIdentity(event);
            Instant callbackAt = clock.instant();
            Thread thread = Thread.currentThread();
            String accessorProvenance = accessorProvenance(accessors);
            String checkSha256 = sha256Utf8(check);
            String stableCheckSha256 = sha256Utf8(stableCheck);
            String semanticFieldsSha256 = sha256Utf8(
                    "player_uuid=" + playerId.toString().toLowerCase() + "\n"
                            + "provider_event_id=" + providerEventId + "\n"
                            + "check_sha256=" + checkSha256 + "\n"
                            + "stable_check_sha256=" + stableCheckSha256 + "\n"
                            + "violation_hex=" + Double.toHexString(violation) + "\n"
                            + "observed_at=" + observedAt + "\n");
            long nextSequence = sequence + 1L;
            List<Field> fields = new ArrayList<>();
            fields.add(new Field("schema", SCHEMA, false));
            fields.add(new Field("sequence", Long.toString(nextSequence), true));
            fields.add(new Field("callback_at", callbackAt.toString(), false));
            fields.add(new Field("capture_attempt_id", captureAttemptId, false));
            fields.add(new Field("capture_challenge_nonce", captureChallenge, false));
            fields.add(new Field("process_id", Long.toString(processId), true));
            fields.add(new Field("process_started_at", processStartedAt, false));
            fields.add(new Field("process_incarnation_sha256", processIncarnationSha256, false));
            fields.add(new Field("owner_plugin_name", owner.getName(), false));
            fields.add(new Field("owner_plugin_version", owner.getPluginMeta().getVersion(), false));
            fields.add(new Field("owner_plugin_main_class", owner.getClass().getName(), false));
            fields.add(new Field("owner_plugin_code_source_sha256", codeSourceSha256(owner.getClass()), false));
            fields.add(new Field("provider_plugin_name", provider.getName(), false));
            fields.add(new Field("provider_plugin_version", provider.getPluginMeta().getVersion(), false));
            fields.add(new Field("provider_plugin_main_class", provider.getClass().getName(), false));
            fields.add(new Field("provider_plugin_code_source_sha256", codeSourceSha256(provider.getClass()), false));
            fields.add(new Field("registered_event_class", registeredEventClass.getName(), false));
            fields.add(new Field("registered_event_code_source_sha256", codeSourceSha256(registeredEventClass), false));
            fields.add(new Field("runtime_event_class", event.getClass().getName(), false));
            fields.add(new Field("runtime_event_code_source_sha256", codeSourceSha256(event.getClass()), false));
            fields.add(new Field("handler_owner_plugin", owner.getName(), false));
            fields.add(new Field("handler_listener_class", listener.getClass().getName(), false));
            fields.add(new Field("handler_priority", EventPriority.MONITOR.name(), false));
            fields.add(new Field("handler_ignore_cancelled", "true", true));
            fields.add(new Field("callback_thread_id", Long.toString(thread.threadId()), true));
            fields.add(new Field("callback_thread_name", thread.getName(), false));
            fields.add(new Field("player_uuid", playerId.toString().toLowerCase(), false));
            fields.add(new Field("provider_event_id_sha256", providerEventId, false));
            fields.add(new Field("check_sha256", checkSha256, false));
            fields.add(new Field("stable_check_sha256", stableCheckSha256, false));
            fields.add(new Field("violation_hex", Double.toHexString(violation), false));
            fields.add(new Field("observed_at", observedAt.toString(), false));
            fields.add(new Field("semantic_fields_sha256", semanticFieldsSha256, false));
            fields.add(new Field("accessor_provenance", accessorProvenance, false));
            fields.add(new Field("accessor_provenance_sha256", sha256Utf8(accessorProvenance), false));
            fields.add(new Field("previous_record_sha256", previousRecordSha256, false));
            String unsigned = json(fields, null);
            String recordSha256 = sha256Utf8(unsigned);
            byte[] bytes = (json(fields, new Field("record_sha256", recordSha256, false)) + "\n")
                    .getBytes(StandardCharsets.UTF_8);
            channel.write(ByteBuffer.wrap(bytes));
            channel.force(true);
            previousRecordSha256 = recordSha256;
            sequence = nextSequence;
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private void assertRuntimeIdentity(Event event) throws IOException {
        if (!registeredEventClass.isInstance(event)
                || event.getClass().getClassLoader() != provider.getClass().getClassLoader()) {
            throw new IOException("runtime event/provider class-loader identity mismatch");
        }
        String providerHash = codeSourceSha256(provider.getClass());
        if (!providerHash.equals(codeSourceSha256(registeredEventClass))
                || !providerHash.equals(codeSourceSha256(event.getClass()))) {
            throw new IOException("runtime event/provider code-source identity mismatch");
        }
    }

    private long channelPositionLineCount() throws IOException {
        // MCAce exclusively owns a newly created, lifetime-locked file.  Position/size equality
        // detects replacement/truncation; the no-follow file-key check also rejects a directory
        // entry swap while the process still holds the original handle.  Sequence is tracked
        // in-process and one callback writes exactly one newline-delimited record.
        BasicFileAttributes attributes = readDirectFileAttributes(ledgerPath);
        if (!ledgerFileKey.equals(attributes.fileKey())) {
            throw new IOException("ledger path identity changed");
        }
        if (channel.position() != channel.size() || attributes.size() != channel.size()) {
            throw new IOException("ledger size changed");
        }
        return sequence;
    }

    static String accessorProvenance(List<Method> methods) throws IOException {
        if (methods == null || methods.isEmpty()) throw new IOException("accessor provenance missing");
        List<String> records = new ArrayList<>();
        for (Method method : methods) {
            if (method == null) continue;
            records.add(method.getDeclaringClass().getName() + "#" + method.getName()
                    + "()->" + method.getReturnType().getTypeName()
                    + "@" + codeSourceSha256(method.getDeclaringClass()));
        }
        if (records.isEmpty()) throw new IOException("accessor provenance missing");
        return String.join(";", records);
    }

    static String codeSourceSha256(Class<?> type) throws IOException {
        try {
            CodeSource source = type.getProtectionDomain().getCodeSource();
            if (source == null || source.getLocation() == null) {
                throw new IOException("code source unavailable for " + type.getName());
            }
            URI uri = source.getLocation().toURI();
            Path path = Path.of(uri).toAbsolutePath().normalize();
            if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) {
                throw new IOException("code source is not a direct file for " + type.getName());
            }
            assertNoSymlinkAncestors(path.getParent());
            BasicFileAttributes before = readDirectFileAttributes(path);
            byte[] bytes = Files.readAllBytes(path);
            BasicFileAttributes after = readDirectFileAttributes(path);
            if (before.fileKey() == null || !before.fileKey().equals(after.fileKey())
                    || before.size() != after.size()
                    || !before.lastModifiedTime().equals(after.lastModifiedTime())
                    || before.size() != bytes.length) {
                throw new IOException("code source changed while hashing " + type.getName());
            }
            return sha256(bytes);
        } catch (IOException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IOException("code source identity failed for " + type.getName(), exception);
        }
    }

    private static void assertNewLedgerPath(Path path) throws IOException {
        Path absolute = path.toAbsolutePath().normalize();
        if (!absolute.equals(path)) throw new IOException("non-canonical provenance path");
        Path parent = absolute.getParent();
        if (parent == null || !Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("provenance parent directory missing");
        }
        assertNoSymlinkAncestors(parent);
        if (Files.exists(absolute, LinkOption.NOFOLLOW_LINKS)) {
            throw new IOException("provenance ledger already exists");
        }
    }

    private static void assertNoSymlinkAncestors(Path parent) throws IOException {
        Path cursor = parent;
        while (cursor != null) {
            if (Files.isSymbolicLink(cursor)) throw new IOException("provenance reparse path rejected");
            cursor = cursor.getParent();
        }
    }

    private static BasicFileAttributes readDirectFileAttributes(Path path) throws IOException {
        if (path == null || Files.isSymbolicLink(path)) {
            throw new IOException("direct file path is unavailable");
        }
        BasicFileAttributes attributes = Files.readAttributes(
                path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
        if (!attributes.isRegularFile()) throw new IOException("direct regular file is required");
        return attributes;
    }

    static String sha256Utf8(String value) throws IOException {
        return sha256(value.getBytes(StandardCharsets.UTF_8));
    }

    private static String sha256(byte[] value) throws IOException {
        try {
            return HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(value));
        } catch (Exception exception) {
            throw new IOException("SHA-256 unavailable", exception);
        }
    }

    private static String json(List<Field> fields, Field tail) {
        StringBuilder output = new StringBuilder("{");
        boolean first = true;
        for (Field field : fields) {
            if (!first) output.append(',');
            first = false;
            appendField(output, field);
        }
        if (tail != null) {
            if (!first) output.append(',');
            appendField(output, tail);
        }
        return output.append('}').toString();
    }

    private static void appendField(StringBuilder output, Field field) {
        output.append('"').append(escape(field.name())).append("\":");
        if (field.raw()) output.append(field.value());
        else output.append('"').append(escape(field.value())).append('"');
    }

    private static String escape(String value) {
        StringBuilder output = new StringBuilder(value.length() + 8);
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            switch (character) {
                case '"' -> output.append("\\\"");
                case '\\' -> output.append("\\\\");
                case '\b' -> output.append("\\b");
                case '\f' -> output.append("\\f");
                case '\n' -> output.append("\\n");
                case '\r' -> output.append("\\r");
                case '\t' -> output.append("\\t");
                default -> {
                    if (character < 0x20) output.append(String.format("\\u%04x", (int) character));
                    else output.append(character);
                }
            }
        }
        return output.toString();
    }

    @Override
    public synchronized void close() {
        if (!enabled) return;
        try {
            if (lock.isValid()) lock.release();
        } catch (IOException ignored) {
            // The evidence runner rejects a missing or unstable final ledger.
        }
        try {
            channel.close();
        } catch (IOException ignored) {
            // The evidence runner rejects a missing or unstable final ledger.
        }
    }

    private record Field(String name, String value, boolean raw) {
        private Field {
            Objects.requireNonNull(name, "name");
            Objects.requireNonNull(value, "value");
        }
    }
}
