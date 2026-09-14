package com.ellan.mcace.client.federation;

import com.ellan.mcace.client.session.ClientHandshakeEngine;
import java.security.MessageDigest;
import java.time.Clock;
import java.util.Arrays;
import java.util.Objects;

/**
 * Connection-local MCAce enablement capability.
 *
 * <p>A human-visible approval is connection-bound immediately and owns exactly one source-export
 * permit. A federation-inherited approval starts provisional, cannot export again, and becomes
 * connection-bound only after the exact one-time presentation was handed to transport and burned
 * from the volatile vault. This keeps a short-lived grant from silently becoming a transitive or
 * indefinitely provisional authorization.</p>
 */
public final class ConnectionEnablementAuthorization {
    public enum Origin {
        HUMAN_VISIBLE,
        FEDERATION_INHERITED
    }

    private final ClientHandshakeEngine candidate;
    private final long generation;
    private final Origin origin;
    private final FederationTokenVault.TargetHandshakeClaim targetClaim;
    private String reservedSourceExportAssertionId;
    private byte[] reservedSourceExportRequestSha256;
    private boolean sourceExportInFlight;
    private boolean sourceExportCommitted;
    private final EvidenceLineagePermit evidenceLineagePermit;
    private boolean connectionBound;
    private boolean invalidated;

    private ConnectionEnablementAuthorization(
            ClientHandshakeEngine candidate,
            long generation,
            Origin origin,
            FederationTokenVault.TargetHandshakeClaim targetClaim,
            EvidenceLineagePermit evidenceLineagePermit,
            boolean connectionBound) {
        this.candidate = Objects.requireNonNull(candidate, "candidate");
        this.generation = generation;
        this.origin = Objects.requireNonNull(origin, "origin");
        this.targetClaim = targetClaim;
        this.evidenceLineagePermit = Objects.requireNonNull(
                evidenceLineagePermit, "evidenceLineagePermit");
        this.connectionBound = connectionBound;
        if ((origin == Origin.HUMAN_VISIBLE) != (targetClaim == null)) {
            throw new IllegalArgumentException("enablement origin and target claim disagree");
        }
    }

    public static ConnectionEnablementAuthorization humanVisible(
            ClientHandshakeEngine candidate, long generation) {
        return new ConnectionEnablementAuthorization(
                candidate, generation, Origin.HUMAN_VISIBLE, null,
                new EvidenceLineagePermit(), true);
    }

    public static ConnectionEnablementAuthorization federationInherited(
            ClientHandshakeEngine candidate,
            long generation,
            FederationTokenVault.TargetHandshakeClaim targetClaim) {
        Objects.requireNonNull(targetClaim, "targetClaim");
        if (targetClaim.engine() != candidate) {
            throw new IllegalArgumentException("federation target claim belongs to another engine");
        }
        return new ConnectionEnablementAuthorization(
                candidate, generation, Origin.FEDERATION_INHERITED, targetClaim,
                targetClaim.evidenceLineagePermit(), false);
    }

    /** True while this exact connection may continue its current enablement lifecycle. */
    public boolean matches(
            ClientHandshakeEngine expectedCandidate,
            long expectedGeneration,
            FederationTokenVault vault,
            Clock clock) {
        FederationTokenVault.TargetHandshakeClaim provisionalClaim;
        synchronized (this) {
            if (invalidated || candidate != expectedCandidate || generation != expectedGeneration) {
                return false;
            }
            if (connectionBound) {
                return true;
            }
            if (origin != Origin.FEDERATION_INHERITED) {
                return false;
            }
            provisionalClaim = targetClaim;
        }
        // Never hold this authorization monitor while entering the vault. Grant storage takes the
        // inverse path (vault -> exact source authorization), so separating the locks prevents a
        // source-export/target-status deadlock without weakening the final vault identity check.
        return vault.isTargetClaimLive(provisionalClaim, clock);
    }

    /** True only after post-authentication features may run for this connection. */
    public boolean isConnectionBound(
            ClientHandshakeEngine expectedCandidate,
            long expectedGeneration,
            FederationTokenVault vault,
            Clock clock) {
        synchronized (this) {
            if (!connectionBound) {
                return false;
            }
        }
        return matches(expectedCandidate, expectedGeneration, vault, clock);
    }

    /**
     * Returns whether this capability belongs to the exact asynchronous connection generation.
     *
     * <p>This deliberately performs no vault lookup. It is used only to scope cancellation: a
     * delayed callback from generation N may tear down generation N, but it must never revoke or
     * invalidate the capability installed by generation N+1.</p>
     */
    public synchronized boolean owns(
            ClientHandshakeEngine expectedCandidate,
            long expectedGeneration) {
        return !invalidated && candidate == expectedCandidate && generation == expectedGeneration;
    }

    /**
     * Atomically reserves the single source-export budget.
     *
     * <p>An exact request-payload retry is permitted after a local transport failure. A changed
     * request reusing the same assertion ID, a distinct second assertion, a concurrent loser, and
     * every inherited target are rejected.</p>
     */
    public synchronized boolean tryBeginSourceExport(
            String assertionId, byte[] requestPayloadSha256) {
        if (invalidated || origin != Origin.HUMAN_VISIBLE
                || sourceExportCommitted || sourceExportInFlight
                || assertionId == null || assertionId.isBlank()
                || requestPayloadSha256 == null || requestPayloadSha256.length != 32) {
            return false;
        }
        if (reservedSourceExportAssertionId == null) {
            reservedSourceExportAssertionId = assertionId;
            reservedSourceExportRequestSha256 = requestPayloadSha256.clone();
            sourceExportInFlight = true;
            return true;
        }
        if (!sameSourceExport(assertionId, requestPayloadSha256)) {
            return false;
        }
        sourceExportInFlight = true;
        return true;
    }

    /** Makes only the exact in-flight assertion retryable after a local pre-send/send failure. */
    public synchronized boolean releaseSourceExportAfterLocalFailure(
            String assertionId, byte[] requestPayloadSha256) {
        if (invalidated || sourceExportCommitted || !sourceExportInFlight
                || !sameSourceExport(assertionId, requestPayloadSha256)) {
            return false;
        }
        sourceExportInFlight = false;
        return true;
    }

    /** Permanently consumes the exact permit once its response was handed to transport. */
    public synchronized boolean commitSourceExport(
            String assertionId, byte[] requestPayloadSha256) {
        if (invalidated || sourceExportCommitted || !sourceExportInFlight
                || !sameSourceExport(assertionId, requestPayloadSha256)) {
            return false;
        }
        sourceExportInFlight = false;
        sourceExportCommitted = true;
        return true;
    }

    /** Promotes only this exact inherited claim with the vault's one-shot commit receipt. */
    public synchronized boolean promoteAfterPresentationCommit(
            FederationTokenVault.PresentationCommitReceipt receipt) {
        if (invalidated || origin != Origin.FEDERATION_INHERITED || connectionBound
                || receipt == null || !receipt.consumeFor(targetClaim)) {
            return false;
        }
        connectionBound = true;
        return true;
    }

    public synchronized boolean isInheritedProvisional() {
        return !invalidated && origin == Origin.FEDERATION_INHERITED && !connectionBound;
    }

    /**
     * Atomically reserves this connection's sole render-frame capture budget.
     *
     * <p>The visible enablement screen discloses at most one render frame. A second request,
     * including a concurrent request with copied identifiers, is rejected while the exact first
     * request is in flight and after its frame is captured. A zero-content outcome may release the
     * exact reservation so it does not consume the frame budget.</p>
     */
    public synchronized boolean tryBeginEvidenceCapture(String requestId, String evidenceId) {
        if (invalidated || !connectionBound) {
            return false;
        }
        return evidenceLineagePermit.tryBegin(this, requestId, evidenceId);
    }

    /** Releases only the exact request when no render-frame content was captured. */
    public synchronized boolean releaseEvidenceCaptureWithoutContent(
            String requestId, String evidenceId) {
        return !invalidated
                && evidenceLineagePermit.releaseWithoutContent(this, requestId, evidenceId);
    }

    /** Permanently consumes the connection budget as soon as the exact frame has been captured. */
    public synchronized boolean commitEvidenceCapture(String requestId, String evidenceId) {
        return !invalidated && evidenceLineagePermit.commit(this, requestId, evidenceId);
    }

    public synchronized Origin origin() {
        return origin;
    }

    public synchronized FederationTokenVault.TargetHandshakeClaim targetClaim() {
        return targetClaim;
    }

    public synchronized void invalidate() {
        invalidated = true;
        sourceExportInFlight = false;
        evidenceLineagePermit.invalidateOwner(this);
        if (reservedSourceExportRequestSha256 != null) {
            Arrays.fill(reservedSourceExportRequestSha256, (byte) 0);
            reservedSourceExportRequestSha256 = null;
        }
    }

    private boolean sameSourceExport(String assertionId, byte[] requestPayloadSha256) {
        return Objects.equals(reservedSourceExportAssertionId, assertionId)
                && reservedSourceExportRequestSha256 != null
                && requestPayloadSha256 != null
                && requestPayloadSha256.length == 32
                && MessageDigest.isEqual(
                        reservedSourceExportRequestSha256, requestPayloadSha256);
    }

    EvidenceLineagePermit evidenceLineagePermitForGrant(
            ClientHandshakeEngine expectedCandidate, String expectedAssertionId) {
        synchronized (this) {
            if (invalidated || origin != Origin.HUMAN_VISIBLE || !connectionBound
                    || !sourceExportCommitted || candidate != expectedCandidate
                    || !Objects.equals(reservedSourceExportAssertionId, expectedAssertionId)) {
                return null;
            }
            return evidenceLineagePermit;
        }
    }

    static EvidenceLineagePermit detachedEvidenceLineagePermit() {
        // Compatibility-only claims have no authenticated human source lineage. They therefore
        // inherit a fail-closed, already-burned budget instead of manufacturing a new frame.
        return new EvidenceLineagePermit(true);
    }

    /**
     * Opaque process-memory-only frame budget shared by one human approval and its one target
     * federation descendant. It exposes no public mutation API; authorizations are the only
     * objects that can reserve, release, or burn it.
     */
    public static final class EvidenceLineagePermit {
        private ConnectionEnablementAuthorization reservationOwner;
        private String reservedRequestId;
        private String reservedEvidenceId;
        private boolean committed;

        private EvidenceLineagePermit() { }

        private EvidenceLineagePermit(boolean committed) {
            this.committed = committed;
        }

        private synchronized boolean tryBegin(
                ConnectionEnablementAuthorization owner, String requestId, String evidenceId) {
            if (committed || reservationOwner != null
                    || !validIdentifier(requestId) || !validIdentifier(evidenceId)) {
                return false;
            }
            reservationOwner = owner;
            reservedRequestId = requestId;
            reservedEvidenceId = evidenceId;
            return true;
        }

        private synchronized boolean releaseWithoutContent(
                ConnectionEnablementAuthorization owner, String requestId, String evidenceId) {
            if (committed || reservationOwner != owner
                    || !sameRequest(requestId, evidenceId)) {
                return false;
            }
            clearReservation();
            return true;
        }

        private synchronized boolean commit(
                ConnectionEnablementAuthorization owner, String requestId, String evidenceId) {
            if (committed || reservationOwner != owner
                    || !sameRequest(requestId, evidenceId)) {
                return false;
            }
            clearReservation();
            committed = true;
            return true;
        }

        private synchronized void invalidateOwner(ConnectionEnablementAuthorization owner) {
            if (!committed && reservationOwner == owner) {
                clearReservation();
            }
        }

        private boolean sameRequest(String requestId, String evidenceId) {
            return Objects.equals(reservedRequestId, requestId)
                    && Objects.equals(reservedEvidenceId, evidenceId);
        }

        private void clearReservation() {
            reservationOwner = null;
            reservedRequestId = null;
            reservedEvidenceId = null;
        }

        private static boolean validIdentifier(String value) {
            return value != null && !value.isBlank() && value.equals(value.trim())
                    && value.chars().noneMatch(Character::isISOControl);
        }
    }
}
