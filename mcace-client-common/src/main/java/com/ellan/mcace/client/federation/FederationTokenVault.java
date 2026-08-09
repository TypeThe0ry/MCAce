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
        Objects.requireNonNull(grant, "grant");
        Objects.requireNonNull(sourceSessionKeyPair, "sourceSessionKeyPair");
        Objects.requireNonNull(expectedPlayerId, "expectedPlayerId");
        Objects.requireNonNull(clock, "clock");
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
        entries.put(binding.assertionId(), new Entry(binding, grant, sourceSessionKeyPair, deadline));
    }

    /** Builds a target handshake using the retained source-session key without exposing it. */
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
        if (entry == null) {
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
        return Optional.of(new ClientHandshakeEngine(
                playerId, clientVersion, minecraftVersion, buildId, loader, targetServerPublicKey,
                clock, secureRandom, entry.sourceSessionKeyPair));
    }

    /**
     * Creates a one-shot presentation reservation. It remains usable after a local send failure
     * until its monotonic deadline; it is removed only by {@link #commit(PreparedPresentation)},
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
        FederationPresentation presentation = FederationDocuments.presentation(
                entry.grant, entry.sourceSessionKeyPair.getPrivate(), targetAuthenticatedSessionId,
                targetChallengeNonce, clock);
        byte[] encoded = FederationDocuments.encode(presentation);
        entry.presentationBytes = encoded.clone();
        entry.reserved = true;
        return Optional.of(new PreparedPresentation(entry.binding.assertionId(), encoded));
    }

    /** Atomically burns a grant after its exact prepared presentation has been handed to transport. */
    public synchronized boolean commit(PreparedPresentation prepared) {
        Objects.requireNonNull(prepared, "prepared");
        Entry entry = entries.get(prepared.assertionId);
        if (entry == null || !entry.reserved || !Arrays.equals(entry.presentationBytes, prepared.encoded)) {
            return false;
        }
        entries.remove(prepared.assertionId);
        entry.clear();
        prepared.clear();
        return true;
    }

    /** Releases a local transport reservation without consuming the grant. */
    public synchronized void sendFailed(PreparedPresentation prepared) {
        if (prepared == null) {
            return;
        }
        Entry entry = entries.get(prepared.assertionId);
        if (entry != null && entry.reserved && Arrays.equals(entry.presentationBytes, prepared.encoded)) {
            entry.reserved = false;
        }
        prepared.clear();
        purgeExpired();
    }

    public synchronized void revoke(String assertionId) {
        Entry entry = entries.remove(assertionId);
        if (entry != null) {
            entry.clear();
        }
    }

    public synchronized void clear() {
        entries.values().forEach(Entry::clear);
        entries.clear();
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

    /** Opaque prepared bytes; its constructor and contents are never externally mutable. */
    public static final class PreparedPresentation {
        private final String assertionId;
        private byte[] encoded;

        private PreparedPresentation(String assertionId, byte[] encoded) {
            this.assertionId = assertionId;
            this.encoded = encoded.clone();
        }

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
        private boolean reserved;
        private boolean boundTargetKeyVerified;
        private byte[] presentationBytes = new byte[0];

        private Entry(GrantBinding binding, FederationGrant grant, KeyPair sourceSessionKeyPair,
                long monotonicDeadlineMillis) {
            this.binding = binding;
            this.grant = grant;
            this.sourceSessionKeyPair = sourceSessionKeyPair;
            this.monotonicDeadlineMillis = monotonicDeadlineMillis;
        }

        private void clear() {
            // Java key objects cannot reliably zero provider-owned private bytes. Drop every
            // reachable reference immediately and zero the only vault-owned presentation copy.
            Arrays.fill(presentationBytes, (byte) 0);
            presentationBytes = new byte[0];
            grant = null;
            sourceSessionKeyPair = null;
            reserved = false;
            boundTargetKeyVerified = false;
        }
    }

    private record GrantBinding(
            UUID playerId,
            String sourceNetworkId,
            String targetNetworkId,
            String sourceSessionId,
            String assertionId,
            long expiresAtEpochMs,
            byte[] targetKeyId) {
        private GrantBinding {
            targetKeyId = targetKeyId.clone();
        }

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
                    || !MessageDigest.isEqual(consent.getClientPublicKeySha256().toByteArray(),
                            assertion.getClientPublicKeySha256().toByteArray())
                    || !MessageDigest.isEqual(sha256(consent.toByteArray()),
                            assertion.getClientConsentSha256().toByteArray())) {
                throw new FederationException("federation grant bindings do not match");
            }
            return new GrantBinding(player, requireText(consent.getSourceNetworkId(), "source network id"),
                    requireText(consent.getTargetNetworkId(), "target network id"),
                    requireText(consent.getLocalAuthenticatedSessionId(), "source session id"),
                    requireText(consent.getAssertionId(), "assertion id"), consent.getExpiresAtEpochMs(),
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
    }
}
