package com.ellan.mcace.core.proxy;

import com.ellan.mcace.core.admission.SignedAdmissionSnapshotCodec;
import com.ellan.mcace.core.context.BackendContextCodec;
import com.ellan.mcace.core.context.BackendContextException;
import com.ellan.mcace.core.context.BackendContextReport;
import com.ellan.mcace.core.session.AuthenticatedManifest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/**
 * Binds Paper/Folia context to a current proxy-to-backend admission delivery and evaluates it on a
 * bounded audit worker. This class exposes no routing, admission, disconnect, or punishment hook.
 */
public final class ShadowBackendContextRuntime implements AutoCloseable {
    public enum ReceiveStatus {
        ACCEPTED_QUEUED,
        ACCEPTED_NO_MANIFEST,
        ACCEPTED_AUDIT_DROPPED,
        REJECTED_INVALID,
        REJECTED_BINDING,
        REJECTED_REPLAY
    }

    public record ReceiveResult(
            ReceiveStatus status, Optional<ShadowBackendContextSnapshot> acceptedContext) {
        public ReceiveResult {
            Objects.requireNonNull(status, "status");
            acceptedContext = Objects.requireNonNull(acceptedContext, "acceptedContext");
        }
    }

    private static final int MAX_PLAYERS = 4096;
    private static final Duration MAX_BINDING_AGE = Duration.ofMinutes(2);
    private static final int MAX_OUTSTANDING_ADMISSIONS = 8;
    private static final int AUDIT_QUEUE_CAPACITY = 32;

    private final String proxyId;
    private final Clock clock;
    private final BackendContextCodec codec;
    private final AuthenticatedManifestEvaluator evaluator;
    private final Consumer<ShadowBackendContextAuditRecord> auditSink;
    private final ThreadPoolExecutor auditExecutor;
    private final AtomicLong droppedAudits = new AtomicLong();
    private final AtomicLong failedAudits = new AtomicLong();
    private final LinkedHashMap<UUID, AuthenticatedManifest> manifests = new LinkedHashMap<>(16, 0.75f, true);
    private final LinkedHashMap<UUID, Binding> bindings = new LinkedHashMap<>(16, 0.75f, true);

    public ShadowBackendContextRuntime(
            String proxyId,
            AuthenticatedManifestObservationDeriver deriver,
            SharedProxyDispositionPolicyRuntime policyRuntime,
            Clock clock,
            Consumer<ShadowBackendContextAuditRecord> auditSink) {
        this.proxyId = boundedId(proxyId, "proxyId");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.codec = new BackendContextCodec(clock);
        this.evaluator = new AuthenticatedManifestEvaluator(
                Objects.requireNonNull(deriver, "deriver"),
                Objects.requireNonNull(policyRuntime, "policyRuntime"),
                clock);
        this.auditSink = Objects.requireNonNull(auditSink, "auditSink");
        this.auditExecutor = new ThreadPoolExecutor(
                1, 1, 0L, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(AUDIT_QUEUE_CAPACITY),
                new ThreadPoolExecutor.AbortPolicy());
    }

    /** Retains only the latest in-memory authenticated manifest for a current player session. */
    public synchronized void rememberManifest(AuthenticatedManifest manifest) {
        Objects.requireNonNull(manifest, "manifest");
        manifests.put(manifest.playerId(), manifest);
        trim(manifests);
        Binding binding = bindings.get(manifest.playerId());
        if (binding != null && binding.context() != null
                && binding.sessionId().equals(manifest.sessionId())) {
            queue(manifest, binding.context());
        }
    }

    /**
     * Arms one exact backend and admission sequence after the proxy has sent its signed snapshot.
     * Multiple refreshes for the same physical session remain bounded and independently matchable
     * because a slow backend can legitimately answer an earlier in-flight signed snapshot.
     */
    public synchronized void expectBackend(
            UUID playerId, String sessionId, String backendId,
            long admissionTransportSequence, Instant admissionExpiresAt) {
        Objects.requireNonNull(playerId, "playerId");
        Objects.requireNonNull(admissionExpiresAt, "admissionExpiresAt");
        String checkedSession = boundedId(sessionId, "sessionId");
        String checkedBackend = boundedId(backendId, "backendId");
        if (admissionTransportSequence <= 0L) {
            throw new IllegalArgumentException("admissionTransportSequence must be positive");
        }
        Instant expectedAt = clock.instant();
        if (!expectedAt.isBefore(admissionExpiresAt)
                || admissionExpiresAt.isAfter(
                        expectedAt.plus(SignedAdmissionSnapshotCodec.MAX_TRANSPORT_TTL))) {
            throw new IllegalArgumentException("admissionExpiresAt is outside the binding window");
        }
        Binding existing = bindings.get(playerId);
        Binding next = existing != null
                        && existing.sessionId().equals(checkedSession)
                        && existing.backendId().equals(checkedBackend)
                ? existing.withoutExpiredExpectations(expectedAt)
                        .withExpectation(admissionTransportSequence, admissionExpiresAt)
                : Binding.expecting(
                        checkedSession, checkedBackend,
                        admissionTransportSequence, admissionExpiresAt);
        bindings.put(playerId, next);
        trim(bindings);
    }

    /**
     * Accepts only the player/backend/sequence tuple armed by {@link #expectBackend}; backendId is
     * supplied by the proxy's server-connection object and never decoded from the frame.
     */
    public ReceiveResult receive(
            UUID carrierPlayerId, String sourceBackendId, byte[] encodedFrame) {
        Objects.requireNonNull(carrierPlayerId, "carrierPlayerId");
        String sourceBackend;
        try {
            sourceBackend = boundedId(sourceBackendId, "sourceBackendId");
        } catch (IllegalArgumentException exception) {
            return rejected(ReceiveStatus.REJECTED_BINDING);
        }
        BackendContextReport report;
        try {
            report = codec.decode(encodedFrame);
        } catch (BackendContextException | RuntimeException exception) {
            return rejected(ReceiveStatus.REJECTED_INVALID);
        }

        AuthenticatedManifest manifest;
        ShadowBackendContextSnapshot snapshot;
        synchronized (this) {
            Binding binding = bindings.get(carrierPlayerId);
            if (binding == null
                    || !carrierPlayerId.equals(report.playerId())
                    || !binding.backendId().equals(sourceBackend)) {
                return rejected(ReceiveStatus.REJECTED_BINDING);
            }
            binding = binding.withoutExpiredExpectations(clock.instant());
            bindings.put(carrierPlayerId, binding);
            if (report.admissionTransportSequence() < binding.confirmedAdmissionSequence()) {
                return rejected(report.reportSequence() <= binding.lastReportSequence()
                        ? ReceiveStatus.REJECTED_REPLAY
                        : ReceiveStatus.REJECTED_BINDING);
            }
            if (!binding.expects(report.admissionTransportSequence())) {
                return rejected(ReceiveStatus.REJECTED_BINDING);
            }
            if (report.reportSequence() <= binding.lastReportSequence()) {
                return rejected(ReceiveStatus.REJECTED_REPLAY);
            }
            snapshot = ShadowBackendContextSnapshot.from(
                    binding.sessionId(), proxyId, sourceBackend, report);
            bindings.put(carrierPlayerId, binding.withReport(
                    report.admissionTransportSequence(), report.reportSequence(), snapshot));
            manifest = manifests.get(carrierPlayerId);
            if (manifest == null || !binding.sessionId().equals(manifest.sessionId())) {
                return new ReceiveResult(ReceiveStatus.ACCEPTED_NO_MANIFEST, Optional.of(snapshot));
            }
        }
        return new ReceiveResult(
                queue(manifest, snapshot)
                        ? ReceiveStatus.ACCEPTED_QUEUED
                        : ReceiveStatus.ACCEPTED_AUDIT_DROPPED,
                Optional.of(snapshot));
    }

    public synchronized Optional<ShadowBackendContextSnapshot> current(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        Binding binding = bindings.get(playerId);
        if (binding == null || binding.context() == null
                || !clock.instant().isBefore(binding.context().expiresAt())) {
            return Optional.empty();
        }
        return Optional.of(binding.context());
    }

    public synchronized void clear(UUID playerId) {
        Objects.requireNonNull(playerId, "playerId");
        manifests.remove(playerId);
        bindings.remove(playerId);
    }

    public synchronized void expire() {
        Instant now = clock.instant();
        bindings.replaceAll((playerId, binding) -> binding.withoutExpiredExpectations(now));
        bindings.entrySet().removeIf(entry -> entry.getValue().expectedAdmissions().isEmpty()
                && (entry.getValue().context() == null
                || !now.isBefore(entry.getValue().context().expiresAt())));
        manifests.entrySet().removeIf(entry -> {
            Binding binding = bindings.get(entry.getKey());
            if (binding != null) {
                return !binding.sessionId().equals(entry.getValue().sessionId());
            }
            // Authentication can complete before the backend connection is ready to receive its
            // first signed admission snapshot. Keep that pre-binding manifest for the same bounded
            // window as a backend binding; disconnect/replacement still clears it immediately.
            return !now.isBefore(entry.getValue().authenticatedAt().plus(MAX_BINDING_AGE));
        });
    }

    public long droppedAuditCount() {
        return droppedAudits.get();
    }

    public long failedAuditCount() {
        return failedAudits.get();
    }

    @Override
    public synchronized void close() {
        manifests.clear();
        bindings.clear();
        auditExecutor.shutdownNow();
    }

    private boolean queue(AuthenticatedManifest manifest, ShadowBackendContextSnapshot snapshot) {
        try {
            auditExecutor.execute(() -> audit(manifest, snapshot));
            return true;
        } catch (RejectedExecutionException exception) {
            droppedAudits.incrementAndGet();
            return false;
        }
    }

    private void audit(AuthenticatedManifest manifest, ShadowBackendContextSnapshot snapshot) {
        try {
            synchronized (this) {
                Binding current = bindings.get(snapshot.playerId());
                if (current == null || current.context() == null
                        || !current.sessionId().equals(manifest.sessionId())
                        || current.confirmedAdmissionSequence() != snapshot.admissionTransportSequence()
                        || current.context().reportSequence() != snapshot.reportSequence()) {
                    return;
                }
            }
            AuthenticatedManifestAuditResult result = evaluator.evaluate(
                    manifest, snapshot.evaluationContext(clock.instant()));
            auditSink.accept(new ShadowBackendContextAuditRecord(
                    result.playerId(), snapshot.proxyId(), snapshot.backendId(), snapshot.worldId(),
                    snapshot.gameMode(), snapshot.observedAt(), clock.instant(),
                    result.evaluation().totalObservations(), result.consistencyIssues().size(),
                    result.evaluation().actionCounts(), result.evaluation().refreshStatus()));
        } catch (RuntimeException exception) {
            failedAudits.incrementAndGet();
        }
    }

    private static ReceiveResult rejected(ReceiveStatus status) {
        return new ReceiveResult(status, Optional.empty());
    }

    private static String boundedId(String value, String field) {
        Objects.requireNonNull(value, field);
        if (value.isBlank() || value.length() > 128
                || value.chars().anyMatch(character -> Character.isISOControl(character))) {
            throw new IllegalArgumentException(field + " is invalid");
        }
        return value;
    }

    private static <V> void trim(LinkedHashMap<UUID, V> map) {
        while (map.size() > MAX_PLAYERS) {
            UUID eldest = map.keySet().iterator().next();
            map.remove(eldest);
        }
    }

    private record Binding(
            String sessionId,
            String backendId,
            NavigableMap<Long, Instant> expectedAdmissions,
            long confirmedAdmissionSequence,
            long lastReportSequence,
            ShadowBackendContextSnapshot context) {
        private Binding {
            Objects.requireNonNull(sessionId, "sessionId");
            Objects.requireNonNull(backendId, "backendId");
            Objects.requireNonNull(expectedAdmissions, "expectedAdmissions");
            TreeMap<Long, Instant> checked = new TreeMap<>();
            expectedAdmissions.forEach((sequence, expiresAt) -> {
                if (sequence == null || sequence <= 0L) {
                    throw new IllegalArgumentException("expected admission sequence must be positive");
                }
                checked.put(sequence, Objects.requireNonNull(expiresAt, "expiresAt"));
            });
            expectedAdmissions = Collections.unmodifiableNavigableMap(checked);
            if (confirmedAdmissionSequence < 0L || lastReportSequence < 0L) {
                throw new IllegalArgumentException("confirmed sequences must not be negative");
            }
        }

        private static Binding expecting(
                String sessionId, String backendId, long sequence, Instant expiresAt) {
            return new Binding(
                    sessionId, backendId, new TreeMap<>(Map.of(sequence, expiresAt)), 0L, 0L, null);
        }

        private boolean expects(long sequence) {
            return expectedAdmissions.containsKey(sequence);
        }

        private Binding withExpectation(long sequence, Instant expiresAt) {
            if (sequence < confirmedAdmissionSequence || expectedAdmissions.containsKey(sequence)) {
                return this;
            }
            TreeMap<Long, Instant> next = new TreeMap<>(expectedAdmissions);
            next.put(sequence, Objects.requireNonNull(expiresAt, "expiresAt"));
            while (next.size() > MAX_OUTSTANDING_ADMISSIONS) {
                next.pollFirstEntry();
            }
            return new Binding(
                    sessionId, backendId, next, confirmedAdmissionSequence, lastReportSequence, context);
        }

        private Binding withoutExpiredExpectations(Instant now) {
            TreeMap<Long, Instant> next = new TreeMap<>(expectedAdmissions);
            next.entrySet().removeIf(entry -> !now.isBefore(entry.getValue()));
            return next.equals(expectedAdmissions)
                    ? this
                    : new Binding(
                            sessionId, backendId, next,
                            confirmedAdmissionSequence, lastReportSequence, context);
        }

        private Binding withReport(
                long admissionSequence, long reportSequence,
                ShadowBackendContextSnapshot acceptedContext) {
            TreeMap<Long, Instant> remaining = new TreeMap<>(expectedAdmissions);
            remaining.headMap(admissionSequence, false).clear();
            return new Binding(
                    sessionId, backendId, remaining, admissionSequence, reportSequence,
                    Objects.requireNonNull(acceptedContext, "acceptedContext"));
        }
    }
}
