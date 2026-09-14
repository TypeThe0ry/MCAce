package com.ellan.mcace.client.federation;

import com.ellan.mcace.client.session.ClientHandshakeEngine;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.federation.FederationDocuments;
import com.ellan.mcace.protocol.federation.FederationException;
import com.ellan.mcace.protocol.generated.ClientFederationConsent;
import com.ellan.mcace.protocol.generated.FederationAssertion;
import com.ellan.mcace.protocol.generated.FederationGrant;
import com.ellan.mcace.protocol.generated.FederationPresentation;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.google.protobuf.InvalidProtocolBufferException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.LongSupplier;

/**
 * Process-memory-only, bounded holder for a player-approved federation grant.
 *
 * <p>This intentionally has no file, preferences, serialization, logging, or public private-key
 * accessor. A grant stays usable only for its monotonic deadline and only for the exact signed
 * target network. A successful caller explicitly commits its prepared presentation; a local send
 * failure releases the reservation without treating the player as suspicious.
 */
public final class FederationTokenVault implements AutoCloseable {
    public static final int DEFAULT_MAX_ENTRIES = 4;
    private static final int MAX_APPROVED_EXPLICIT_FILES = 128;
    private static final int MAX_APPROVED_EXPLICIT_FILE_CHARS = 512;

    private final int maxEntries;
    private final LongSupplier monotonicMillis;
    private final Map<String, Entry> entries = new LinkedHashMap<>();

    public FederationTokenVault() {
        this(DEFAULT_MAX_ENTRIES, () -> System.nanoTime() / 1_000_000L);
    }

    FederationTokenVault(int maxEntries, LongSupplier monotonicMillis) {
        if (maxEntries < 1) {
            throw new IllegalArgumentException("maxEntries must be positive");
        }
        this.maxEntries = maxEntries;
        this.monotonicMillis = Objects.requireNonNull(monotonicMillis, "monotonicMillis");
    }

    /**
     * Stores only a grant bound to the currently authenticated source session. The source server's
     * envelope is authenticated by the handshake engine before this method is reached; the target
     * later independently verifies the source assertion signature and the client PoP.
     */
    public synchronized void store(
            FederationGrant grant,
            KeyPair sourceSessionKeyPair,
            UUID expectedPlayerId,
            String expectedSourceSessionId,
            Clock clock) throws FederationException {
        store(grant, sourceSessionKeyPair, expectedPlayerId, expectedSourceSessionId, clock, Set.of());
    }

    /**
     * Stores the exact explicit-file scope covered by the source connection's visible approval
     * together with the one-time grant. A target never inherits a process-global consent bit.
     */
    public synchronized void store(
            FederationGrant grant,
            KeyPair sourceSessionKeyPair,
            UUID expectedPlayerId,
            String expectedSourceSessionId,
            Clock clock,
            Set<String> approvedExplicitFiles) throws FederationException {
        storeInternal(
                grant,
                sourceSessionKeyPair,
                expectedPlayerId,
                expectedSourceSessionId,
                clock,
                approvedExplicitFiles,
                ConnectionEnablementAuthorization.detachedEvidenceLineagePermit());
    }

    /**
     * Stores a grant together with the exact process-local evidence budget created by the source
     * connection's visible approval.
     *
     * <p>The source export must already have been committed on this exact handshake engine. This
     * prevents a copied grant, a different connection authorization, or an inherited target from
     * manufacturing a fresh render-frame budget during federation handoff.</p>
     */
    public synchronized void store(
            FederationGrant grant,
            KeyPair sourceSessionKeyPair,
            UUID expectedPlayerId,
            String expectedSourceSessionId,
            Clock clock,
            Set<String> approvedExplicitFiles,
            ClientHandshakeEngine expectedSourceEngine,
            ConnectionEnablementAuthorization sourceAuthorization) throws FederationException {
        Objects.requireNonNull(expectedSourceEngine, "expectedSourceEngine");
        Objects.requireNonNull(sourceAuthorization, "sourceAuthorization");
        ConnectionEnablementAuthorization.EvidenceLineagePermit evidenceLineagePermit =
                sourceAuthorization.evidenceLineagePermitForGrant(
                        expectedSourceEngine,
                        grant == null || !grant.hasClientConsent()
                                ? null
                                : grant.getClientConsent().getAssertionId());
        if (evidenceLineagePermit == null) {
            throw new FederationException(
                    "federation grant is not bound to a committed human source authorization");
        }
        storeInternal(
                grant,
                sourceSessionKeyPair,
                expectedPlayerId,
                expectedSourceSessionId,
                clock,
                approvedExplicitFiles,
                evidenceLineagePermit);
    }

    private void storeInternal(
            FederationGrant grant,
            KeyPair sourceSessionKeyPair,
            UUID expectedPlayerId,
            String expectedSourceSessionId,
            Clock clock,
            Set<String> approvedExplicitFiles,
            ConnectionEnablementAuthorization.EvidenceLineagePermit evidenceLineagePermit)
            throws FederationException {
        Objects.requireNonNull(grant, "grant");
        Objects.requireNonNull(sourceSessionKeyPair, "sourceSessionKeyPair");
        Objects.requireNonNull(expectedPlayerId, "expectedPlayerId");
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(evidenceLineagePermit, "evidenceLineagePermit");
        Set<String> approvedScope = copyApprovedExplicitFiles(approvedExplicitFiles);
        String sourceSessionId = requireText(expectedSourceSessionId, "source session id");
        purgeExpired();

        GrantBinding binding = GrantBinding.from(grant, sourceSessionKeyPair.getPublic());
        if (!binding.playerId().equals(expectedPlayerId) || !binding.sourceSessionId().equals(sourceSessionId)) {
            throw new FederationException("federation grant is not bound to this source session");
        }
        long remaining = remainingWallMillis(binding.expiresAtEpochMs(), clock.millis());
        if (remaining <= 0L) {
            throw new FederationException("federation grant is expired");
        }
        long deadline = saturatedAdd(monotonicMillis.getAsLong(), remaining);
        Entry existing = entries.remove(binding.assertionId());
        if (existing != null) {
            existing.clear();
        }
        // A newer player-approved grant replaces (and clears) the older grant for this exact
        // player/target pair. We never silently retain an ambiguous older signing capability.
        Iterator<Entry> sameTarget = entries.values().iterator();
        while (sameTarget.hasNext()) {
            Entry candidate = sameTarget.next();
            if (candidate.binding.playerId().equals(binding.playerId())
                    && candidate.binding.targetNetworkId().equals(binding.targetNetworkId())) {
                sameTarget.remove();
                candidate.clear();
            }
        }
        if (entries.size() >= maxEntries) {
            // Never evict a different active player-approved grant to make room for new work.
            throw new FederationException("federation transfer vault is full");
        }
        entries.put(binding.assertionId(),
                new Entry(
                        binding,
                        grant,
                        sourceSessionKeyPair,
                        deadline,
                        approvedScope,
                        evidenceLineagePermit));
    }

    /**
     * Builds a target handshake using the retained source-session key without exposing it.
     *
     * <p>This compatibility entry point is deliberately limited to grants whose visible source
     * approval contained no explicit-file scope. A scoped approval must be consumed through
     * {@link #claimTargetHandshake} so a caller cannot accidentally discard the scope and turn a
     * narrow approval into an unbounded target handshake.</p>
     */
    public synchronized Optional<ClientHandshakeEngine> newTargetHandshake(
            String targetNetworkId,
            UUID playerId,
            String clientVersion,
            String minecraftVersion,
            String buildId,
            LoaderType loader,
            PublicKey targetServerPublicKey,
            Clock clock,
            SecureRandom secureRandom) throws EnvelopeException {
        Entry entry = activeFor(targetNetworkId, playerId);
        if (entry != null && !entry.approvedExplicitFiles.isEmpty()) {
            return Optional.empty();
        }
        return claimTargetHandshake(
                targetNetworkId, playerId, clientVersion, minecraftVersion,
                buildId, loader, targetServerPublicKey, clock, secureRandom)
                .map(TargetHandshakeClaim::engine);
    }

    /**
     * Atomically claims the exact target handshake and the source-approved file scope carried by
     * the same one-time vault entry. The returned scope is immutable and cannot outlive a second
     * claim because the entry's target-key claim bit is set before this method returns.
     */
    public synchronized Optional<TargetHandshakeClaim> claimTargetHandshake(
            String targetNetworkId,
            UUID playerId,
            String clientVersion,
            String minecraftVersion,
            String buildId,
            LoaderType loader,
            PublicKey targetServerPublicKey,
            Clock clock,
            SecureRandom secureRandom) throws EnvelopeException {
        Objects.requireNonNull(clock, "clock");
        Entry entry = activeFor(targetNetworkId, playerId);
        if (entry == null) {
            return Optional.empty();
        }
        if (entry.binding.expiresAtEpochMs() <= clock.millis()) {
            entries.remove(entry.binding.assertionId());
            entry.clear();
            return Optional.empty();
        }
        if (entry.boundTargetKeyVerified) {
            // The exact short-lived grant may seed only one target connection. A retry must
            // obtain a new visible source export instead of cloning the retained key into a
            // second or stale connection.
            return Optional.empty();
        }
        if (!MessageDigest.isEqual(entry.binding.targetKeyId(), sha256(targetServerPublicKey.getEncoded()))) {
            // Never expose the source-session key to a same-name network with a different
            // identity key. This is a non-destructive mismatch: callers must authenticate a
            // SERVER_HELLO before they use its target ID, and an untrusted/provisional ID must
            // not be able to erase a player-approved grant for the real pinned target.
            return Optional.empty();
        }
        entry.boundTargetKeyVerified = true;
        ClientHandshakeEngine engine = new ClientHandshakeEngine(
                playerId, clientVersion, minecraftVersion, buildId, loader, targetServerPublicKey,
                clock, secureRandom, entry.sourceSessionKeyPair,
                entry.binding.signedAssertionSha256());
        TargetHandshakeClaim claim = new TargetHandshakeClaim(
                engine,
                entry.approvedExplicitFiles,
                entry.binding.assertionId(),
                entry.binding.targetNetworkId(),
                entry.binding.expiresAtEpochMs(),
                entry.monotonicDeadlineMillis,
                entry.evidenceLineagePermit);
        entry.targetClaim = claim;
        return Optional.of(claim);
    }

    /**
     * Checks that an exact provisional target claim still owns the live, unexpired vault entry.
     * Object identity prevents a caller from fabricating a claim with copied public fields.
     */
    public synchronized boolean isTargetClaimLive(TargetHandshakeClaim claim, Clock clock) {
        Objects.requireNonNull(claim, "claim");
        Objects.requireNonNull(clock, "clock");
        purgeExpired();
        Entry entry = entries.get(claim.assertionId());
        if (entry == null || entry.targetClaim != claim || !entry.boundTargetKeyVerified) {
            return false;
        }
        if (entry.binding.expiresAtEpochMs() <= clock.millis()) {
            entries.remove(entry.binding.assertionId());
            entry.clear();
            return false;
        }
        return true;
    }

    /**
     * Creates a one-shot presentation reservation. It remains usable after a local send failure
     * until its monotonic deadline; it is removed only by {@link #commit(PreparedPresentation, Clock)},
     * expiry, explicit revocation, or shutdown.
     */
    public synchronized Optional<PreparedPresentation> preparePresentation(
            String targetNetworkId,
            UUID playerId,
            String targetAuthenticatedSessionId,
            byte[] targetChallengeNonce,
            Clock clock) throws FederationException {
        Entry entry = activeFor(targetNetworkId, playerId);
        if (entry == null || entry.reserved || !entry.boundTargetKeyVerified) {
            return Optional.empty();
        }
        Objects.requireNonNull(clock, "clock");
        if (entry.binding.expiresAtEpochMs() <= clock.millis()) {
            entries.remove(entry.binding.assertionId());
            entry.clear();
            return Optional.empty();
        }
        FederationPresentation presentation = FederationDocuments.presentation(
                entry.grant, entry.sourceSessionKeyPair.getPrivate(), targetAuthenticatedSessionId,
                targetChallengeNonce, clock);
        byte[] encoded = FederationDocuments.encode(presentation);
        entry.presentationBytes = encoded.clone();
        entry.reserved = true;
        PreparedPresentation prepared = new PreparedPresentation(
                entry.binding.assertionId(),
                entry.binding.sourceNetworkId(),
                entry.binding.targetNetworkId(),
                entry.binding.sourceKeyId(),
                entry.binding.targetKeyId(),
                entry.binding.disclosure(),
                entry.binding.issuedAtEpochMs(),
                entry.binding.expiresAtEpochMs(),
                encoded);
        entry.reservation = prepared;
        return Optional.of(prepared);
    }

    /**
     * Atomically burns a grant after its exact prepared presentation has been handed to transport.
     *
     * <p>The returned one-shot receipt is the only capability that can promote the matching
     * provisional connection authorization. Merely holding or copying the public target-claim
     * metadata is intentionally insufficient.</p>
     */
    public synchronized Optional<PresentationCommitReceipt> commit(
            PreparedPresentation prepared,
            Clock clock) {
        Objects.requireNonNull(prepared, "prepared");
        Objects.requireNonNull(clock, "clock");
        purgeExpired();
        Entry entry = entries.get(prepared.assertionId);
        if (entry == null || !entry.reserved || entry.reservation != prepared
                || entry.targetClaim == null
                || !Arrays.equals(entry.presentationBytes, prepared.encoded)) {
            prepared.clear();
            return Optional.empty();
        }
        if (prepared.expiresAtEpochMs <= clock.millis()) {
            entries.remove(prepared.assertionId);
            entry.clear();
            return Optional.empty();
        }
        TargetHandshakeClaim committedClaim = entry.targetClaim;
        entries.remove(prepared.assertionId);
        entry.clear();
        return Optional.of(new PresentationCommitReceipt(committedClaim));
    }

    /** Burns only the exact visible-prompt capability after an explicit Decline or close action. */
    public synchronized boolean decline(PreparedPresentation prepared) {
        return burn(prepared);
    }

    /** Checks that the exact object shown to the player is still reserved and unexpired. */
    public synchronized boolean isReserved(PreparedPresentation prepared, Clock clock) {
        Objects.requireNonNull(prepared, "prepared");
        Objects.requireNonNull(clock, "clock");
        purgeExpired();
        Entry entry = entries.get(prepared.assertionId);
        if (entry == null || !entry.reserved || entry.reservation != prepared
                || !Arrays.equals(entry.presentationBytes, prepared.encoded)) {
            return false;
        }
        if (prepared.expiresAtEpochMs <= clock.millis()) {
            entries.remove(prepared.assertionId);
            entry.clear();
            return false;
        }
        return true;
    }

    /** Releases a local transport reservation without consuming the grant. */
    public synchronized void sendFailed(PreparedPresentation prepared) {
        if (prepared == null) {
            return;
        }
        Entry entry = entries.get(prepared.assertionId);
        if (entry != null && entry.reserved && entry.reservation == prepared
                && Arrays.equals(entry.presentationBytes, prepared.encoded)) {
            Arrays.fill(entry.presentationBytes, (byte) 0);
            entry.presentationBytes = new byte[0];
            entry.reserved = false;
            entry.reservation = null;
        }
        prepared.clear();
        purgeExpired();
    }

    private boolean burn(PreparedPresentation prepared) {
        Objects.requireNonNull(prepared, "prepared");
        purgeExpired();
        Entry entry = entries.get(prepared.assertionId);
        if (entry == null || !entry.reserved || entry.reservation != prepared
                || !Arrays.equals(entry.presentationBytes, prepared.encoded)) {
            prepared.clear();
            return false;
        }
        entries.remove(prepared.assertionId);
        entry.clear();
        return true;
    }

    public synchronized void revoke(String assertionId) {
        Entry entry = entries.remove(assertionId);
        if (entry != null) {
            entry.clear();
        }
    }

    /**
     * Advances the volatile handoff lifecycle without destroying a just-exported source grant.
     *
     * <p>An unclaimed grant may cross exactly one source disconnect so the player can join its
     * signed target. A claimed target connection, a reserved target prompt, or a second unrelated
     * disconnect clears the entry. This never creates storage or a transport of its own.
     */
    public synchronized void onConnectionClosed() {
        cancelTargetClaims();
        purgeExpired();
        Iterator<Entry> iterator = entries.values().iterator();
        while (iterator.hasNext()) {
            Entry entry = iterator.next();
            if (entry.sourceConnectionClosed) {
                iterator.remove();
                entry.clear();
            } else {
                entry.sourceConnectionClosed = true;
            }
        }
    }

    /**
     * Clears every target-side claim owned by this vault while preserving an unclaimed source
     * grant for the one allowed source disconnect. This is the connection-wide counterpart to
     * {@link #cancelTargetClaim(TargetHandshakeClaim)} and is idempotent for lifecycle cleanup.
     */
    public synchronized void cancelTargetClaims() {
        purgeExpired();
        Iterator<Entry> iterator = entries.values().iterator();
        while (iterator.hasNext()) {
            Entry entry = iterator.next();
            if (entry.boundTargetKeyVerified) {
                iterator.remove();
                entry.clear();
            }
        }
    }

    /**
     * Clears only the exact target connection claim that is aborting. Object identity prevents a
     * delayed generation from revoking a newer connection's claim for the same player/target.
     */
    public synchronized boolean cancelTargetClaim(TargetHandshakeClaim claim) {
        Objects.requireNonNull(claim, "claim");
        purgeExpired();
        Entry entry = entries.get(claim.assertionId());
        if (entry == null || entry.targetClaim != claim || !entry.boundTargetKeyVerified) {
            return false;
        }
        entries.remove(claim.assertionId());
        entry.clear();
        return true;
    }

    public synchronized void clear() {
        entries.values().forEach(Entry::clear);
        entries.clear();
    }

    /** Eagerly drops expired key material while the client remains on a title or consent screen. */
    public synchronized void discardExpired(Clock clock) {
        Objects.requireNonNull(clock, "clock");
        purgeExpired();
        Iterator<Entry> iterator = entries.values().iterator();
        while (iterator.hasNext()) {
            Entry entry = iterator.next();
            if (entry.binding.expiresAtEpochMs() <= clock.millis()) {
                iterator.remove();
                entry.clear();
            }
        }
    }

    public synchronized int size() {
        purgeExpired();
        return entries.size();
    }

    @Override
    public synchronized void close() {
        clear();
    }

    private Entry activeFor(String targetNetworkId, UUID playerId) {
        String target = requireText(targetNetworkId, "target network id");
        Objects.requireNonNull(playerId, "playerId");
        purgeExpired();
        for (Entry entry : entries.values()) {
            if (entry.binding.targetNetworkId().equals(target) && entry.binding.playerId().equals(playerId)) {
                return entry;
            }
        }
        return null;
    }

    private void purgeExpired() {
        long now = monotonicMillis.getAsLong();
        Iterator<Entry> iterator = entries.values().iterator();
        while (iterator.hasNext()) {
            Entry entry = iterator.next();
            if (now >= entry.monotonicDeadlineMillis) {
                iterator.remove();
                entry.clear();
            }
        }
    }

    private static long remainingWallMillis(long expiresAt, long now) throws FederationException {
        if (expiresAt <= now) {
            return 0L;
        }
        long remaining;
        try {
            remaining = Math.subtractExact(expiresAt, now);
        } catch (ArithmeticException exception) {
            throw new FederationException("federation expiry overflow", exception);
        }
        long maximum = ProtocolConstants.MAX_FEDERATION_ASSERTION_TTL.toMillis();
        return Math.min(remaining, maximum);
    }

    private static long saturatedAdd(long start, long duration) {
        if (duration <= 0L || start > Long.MAX_VALUE - duration) {
            return Long.MAX_VALUE;
        }
        return start + duration;
    }

    private static byte[] sha256(byte[] input) throws EnvelopeException {
        try {
            return MessageDigest.getInstance("SHA-256").digest(input);
        } catch (NoSuchAlgorithmException exception) {
            throw new EnvelopeException("SHA-256 is unavailable", exception);
        }
    }

    private static String requireText(String value, String label) {
        if (value == null || value.isBlank() || value.length() > ProtocolConstants.MAX_FEDERATION_ID_CHARS) {
            throw new IllegalArgumentException("invalid " + label);
        }
        return value;
    }

    private static Set<String> copyApprovedExplicitFiles(Set<String> approvedExplicitFiles)
            throws FederationException {
        if (approvedExplicitFiles == null || approvedExplicitFiles.size() > MAX_APPROVED_EXPLICIT_FILES) {
            throw new FederationException("invalid federation-approved explicit-file scope");
        }
        for (String path : approvedExplicitFiles) {
            if (path == null || path.isBlank() || path.length() > MAX_APPROVED_EXPLICIT_FILE_CHARS
                    || path.chars().anyMatch(Character::isISOControl)
                    || !canonicalRelativeExplicitFile(path)) {
                throw new FederationException("invalid federation-approved explicit-file path");
            }
        }
        return Set.copyOf(approvedExplicitFiles);
    }

    private static boolean canonicalRelativeExplicitFile(String path) {
        if (path.startsWith("/") || path.endsWith("/") || path.contains("\\")
                || path.contains("//") || path.indexOf(':') >= 0) {
            return false;
        }
        for (String component : path.split("/", -1)) {
            if (component.isEmpty() || component.equals(".") || component.equals("..")) {
                return false;
            }
        }
        return true;
    }

    /** Opaque target claim carrying immutable lifecycle metadata, never private-key bytes. */
    public record TargetHandshakeClaim(
            ClientHandshakeEngine engine,
            Set<String> approvedExplicitFiles,
            String assertionId,
            String targetNetworkId,
            long expiresAtEpochMs,
            long monotonicDeadlineMillis,
            ConnectionEnablementAuthorization.EvidenceLineagePermit evidenceLineagePermit) {
        public TargetHandshakeClaim {
            engine = Objects.requireNonNull(engine, "engine");
            approvedExplicitFiles = Set.copyOf(approvedExplicitFiles);
            assertionId = requireText(assertionId, "assertion id");
            targetNetworkId = requireText(targetNetworkId, "target network id");
            evidenceLineagePermit = Objects.requireNonNull(
                    evidenceLineagePermit, "evidenceLineagePermit");
            if (expiresAtEpochMs <= 0L) {
                throw new IllegalArgumentException("invalid federation target claim deadline");
            }
        }

        /** Compatibility constructor for isolated tests and callers without a source lineage. */
        public TargetHandshakeClaim(
                ClientHandshakeEngine engine,
                Set<String> approvedExplicitFiles,
                String assertionId,
                String targetNetworkId,
                long expiresAtEpochMs,
                long monotonicDeadlineMillis) {
            this(
                    engine,
                    approvedExplicitFiles,
                    assertionId,
                    targetNetworkId,
                    expiresAtEpochMs,
                    monotonicDeadlineMillis,
                    ConnectionEnablementAuthorization.detachedEvidenceLineagePermit());
        }
    }

    /**
     * Opaque, non-constructible, one-shot proof that the vault burned the exact target claim.
     * Only the federation authorization state machine in this package can consume it.
     */
    public static final class PresentationCommitReceipt {
        private TargetHandshakeClaim committedClaim;

        private PresentationCommitReceipt(TargetHandshakeClaim committedClaim) {
            this.committedClaim = Objects.requireNonNull(committedClaim, "committedClaim");
        }

        synchronized boolean consumeFor(TargetHandshakeClaim expectedClaim) {
            if (committedClaim == null || committedClaim != expectedClaim) {
                return false;
            }
            committedClaim = null;
            return true;
        }
    }

    /** Opaque prepared bytes; its constructor and contents are never externally mutable. */
    public static final class PreparedPresentation {
        private final String assertionId;
        private final String sourceNetworkId;
        private final String targetNetworkId;
        private final byte[] sourceKeyId;
        private final byte[] targetKeyId;
        private final String disclosure;
        private final long issuedAtEpochMs;
        private final long expiresAtEpochMs;
        private byte[] encoded;

        private PreparedPresentation(
                String assertionId,
                String sourceNetworkId,
                String targetNetworkId,
                byte[] sourceKeyId,
                byte[] targetKeyId,
                String disclosure,
                long issuedAtEpochMs,
                long expiresAtEpochMs,
                byte[] encoded) {
            this.assertionId = assertionId;
            this.sourceNetworkId = sourceNetworkId;
            this.targetNetworkId = targetNetworkId;
            this.sourceKeyId = sourceKeyId.clone();
            this.targetKeyId = targetKeyId.clone();
            this.disclosure = disclosure;
            this.issuedAtEpochMs = issuedAtEpochMs;
            this.expiresAtEpochMs = expiresAtEpochMs;
            this.encoded = encoded.clone();
        }

        public String sourceNetworkId() { return sourceNetworkId; }

        public String targetNetworkId() { return targetNetworkId; }

        public byte[] sourceKeyId() { return sourceKeyId.clone(); }

        public byte[] targetKeyId() { return targetKeyId.clone(); }

        public String disclosure() { return disclosure; }

        public long issuedAtEpochMs() { return issuedAtEpochMs; }

        public long expiresAtEpochMs() { return expiresAtEpochMs; }

        public byte[] encoded() {
            return encoded.clone();
        }

        private void clear() {
            Arrays.fill(encoded, (byte) 0);
            encoded = new byte[0];
        }
    }

    private static final class Entry {
        private final GrantBinding binding;
        private FederationGrant grant;
        private KeyPair sourceSessionKeyPair;
        private final long monotonicDeadlineMillis;
        private final Set<String> approvedExplicitFiles;
        private final ConnectionEnablementAuthorization.EvidenceLineagePermit evidenceLineagePermit;
        private boolean reserved;
        private boolean boundTargetKeyVerified;
        private boolean sourceConnectionClosed;
        private byte[] presentationBytes = new byte[0];
        private PreparedPresentation reservation;
        private TargetHandshakeClaim targetClaim;

        private Entry(
                GrantBinding binding,
                FederationGrant grant,
                KeyPair sourceSessionKeyPair,
                long monotonicDeadlineMillis,
                Set<String> approvedExplicitFiles,
                ConnectionEnablementAuthorization.EvidenceLineagePermit evidenceLineagePermit) {
            this.binding = binding;
            this.grant = grant;
            this.sourceSessionKeyPair = sourceSessionKeyPair;
            this.monotonicDeadlineMillis = monotonicDeadlineMillis;
            this.approvedExplicitFiles = Set.copyOf(approvedExplicitFiles);
            this.evidenceLineagePermit = Objects.requireNonNull(
                    evidenceLineagePermit, "evidenceLineagePermit");
        }

        private void clear() {
            // Java key objects cannot reliably zero provider-owned private bytes. Drop every
            // reachable reference immediately and zero the only vault-owned presentation copy.
            Arrays.fill(presentationBytes, (byte) 0);
            presentationBytes = new byte[0];
            if (reservation != null) {
                reservation.clear();
                reservation = null;
            }
            grant = null;
            sourceSessionKeyPair = null;
            reserved = false;
            boundTargetKeyVerified = false;
            sourceConnectionClosed = false;
            targetClaim = null;
        }
    }

    private record GrantBinding(
            UUID playerId,
            String sourceNetworkId,
            String targetNetworkId,
            String sourceSessionId,
            String assertionId,
            String disclosure,
            long issuedAtEpochMs,
            long expiresAtEpochMs,
            byte[] signedAssertionSha256,
            byte[] sourceKeyId,
            byte[] targetKeyId) {
        private GrantBinding {
            signedAssertionSha256 = signedAssertionSha256.clone();
            sourceKeyId = sourceKeyId.clone();
            targetKeyId = targetKeyId.clone();
        }

        @Override
        public byte[] signedAssertionSha256() { return signedAssertionSha256.clone(); }

        @Override
        public byte[] sourceKeyId() { return sourceKeyId.clone(); }

        @Override
        public byte[] targetKeyId() { return targetKeyId.clone(); }

        private static GrantBinding from(FederationGrant grant, PublicKey expectedClientPublicKey)
                throws FederationException {
            if (grant.getSchemaVersion() != ProtocolConstants.FEDERATION_SCHEMA_VERSION
                    || !grant.hasClientConsent() || !grant.hasSignedAssertion()
                    || grant.getClientPublicKeyX509().isEmpty()
                    || !Arrays.equals(grant.getClientPublicKeyX509().toByteArray(), expectedClientPublicKey.getEncoded())) {
                throw new FederationException("malformed federation grant");
            }
            ClientFederationConsent consent = grant.getClientConsent();
            FederationAssertion assertion;
            try {
                assertion = FederationAssertion.parseFrom(grant.getSignedAssertion().getAssertion());
            } catch (InvalidProtocolBufferException exception) {
                throw new FederationException("malformed federation assertion", exception);
            }
            UUID player;
            try {
                player = UUID.fromString(consent.getPlayerUuid());
            } catch (IllegalArgumentException exception) {
                throw new FederationException("invalid federation player binding", exception);
            }
            if (consent.getSchemaVersion() != ProtocolConstants.FEDERATION_SCHEMA_VERSION
                    || assertion.getSchemaVersion() != ProtocolConstants.FEDERATION_SCHEMA_VERSION
                    || !consent.getSourceNetworkId().equals(assertion.getSourceNetworkId())
                    || !consent.getTargetNetworkId().equals(assertion.getTargetNetworkId())
                    || !consent.getPlayerUuid().equals(assertion.getPlayerUuid())
                    || !consent.getLocalAuthenticatedSessionId().equals(assertion.getLocalAuthenticatedSessionId())
                    || !consent.getAssertionId().equals(assertion.getAssertionId())
                    || !MessageDigest.isEqual(consent.getAssertionNonce().toByteArray(),
                            assertion.getAssertionNonce().toByteArray())
                    || consent.getIssuedAtEpochMs() != assertion.getIssuedAtEpochMs()
                    || consent.getExpiresAtEpochMs() != assertion.getExpiresAtEpochMs()
                    || assertion.getSourceAuthorizedAtEpochMs() < assertion.getIssuedAtEpochMs()
                    || assertion.getSourceAuthorizedAtEpochMs() >= assertion.getExpiresAtEpochMs()
                    || !consent.getPolicyVersion().equals(assertion.getPolicyVersion())
                    || !MessageDigest.isEqual(consent.getPolicySha256().toByteArray(),
                            assertion.getPolicySha256().toByteArray())
                    || !consent.getDisclosure().equals(assertion.getDisclosure())
                    || !MessageDigest.isEqual(consent.getSourceKeyIdSha256().toByteArray(),
                            assertion.getSourceKeyIdSha256().toByteArray())
                    || !MessageDigest.isEqual(consent.getSourceKeyIdSha256().toByteArray(),
                            grant.getSignedAssertion().getSourceKeyIdSha256().toByteArray())
                    || !MessageDigest.isEqual(consent.getTargetKeyIdSha256().toByteArray(),
                            assertion.getTargetKeyIdSha256().toByteArray())
                    || !MessageDigest.isEqual(consent.getClientPublicKeySha256().toByteArray(),
                            sha256(expectedClientPublicKey.getEncoded()))
                    || !MessageDigest.isEqual(consent.getClientPublicKeySha256().toByteArray(),
                            assertion.getClientPublicKeySha256().toByteArray())
                    || !MessageDigest.isEqual(sha256(consent.toByteArray()),
                            assertion.getClientConsentSha256().toByteArray())) {
                throw new FederationException("federation grant bindings do not match");
            }
            return new GrantBinding(player, requireText(consent.getSourceNetworkId(), "source network id"),
                    requireText(consent.getTargetNetworkId(), "target network id"),
                    requireText(consent.getLocalAuthenticatedSessionId(), "source session id"),
                    requireText(consent.getAssertionId(), "assertion id"),
                    requireDisclosure(consent.getDisclosure()), consent.getIssuedAtEpochMs(),
                    consent.getExpiresAtEpochMs(),
                    requiredSha256(FederationDocuments.signedAssertionSha256(grant),
                            "signed assertion hash"),
                    requiredSha256(consent.getSourceKeyIdSha256().toByteArray(), "source key id"),
                    requiredSha256(consent.getTargetKeyIdSha256().toByteArray(), "target key id"));
        }

        private static byte[] sha256(byte[] input) throws FederationException {
            try {
                return MessageDigest.getInstance("SHA-256").digest(input);
            } catch (java.security.NoSuchAlgorithmException exception) {
                throw new FederationException("SHA-256 is unavailable", exception);
            }
        }

        private static byte[] requiredSha256(byte[] value, String label) throws FederationException {
            if (value == null || value.length != 32) {
                throw new FederationException("invalid federation " + label);
            }
            return value.clone();
        }

        private static String requireDisclosure(String disclosure) throws FederationException {
            if (!FederationDocuments.MINIMAL_DISCLOSURE.equals(disclosure)) {
                throw new FederationException("invalid federation disclosure");
            }
            return disclosure;
        }
    }
}
