package com.ellan.mcace.paper;

import com.ellan.mcace.core.authority.AuthorityProtocolException;
import com.ellan.mcace.core.authority.AuthoritySequenceMismatchException;
import com.ellan.mcace.core.authority.DurableServerAuthorityIssuer;
import com.ellan.mcace.core.authority.DurablyIssuedServerAuthorityObservation;
import com.ellan.mcace.core.authority.ServerAuthorityObservationCodec;
import java.io.IOException;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Inert Paper/Folia orchestration primitive for one durable authority issuance.
 *
 * <p>This type is deliberately package-private and is not instantiated by the production plugin.
 * It registers no channel, selects no provider/profile/key, sends no frame, and has no disposition
 * dependency. Its sole job is to make the already-disabled lifecycle ordering unambiguous: reserve
 * one capability, force the matching journal record, commit that exact token, and only then return
 * the durable capability. The raw frame remains inaccessible outside the core authority package.</p>
 *
 * <p>If durable issuance succeeds but the lifecycle commit fails, the durable sequence has already
 * advanced. The coordinator therefore removes the in-memory lifecycle and permanently poisons
 * itself instead of aborting or retrying. Recovery requires a fresh typed
 * {@code recover(VerifiedGrant)} result; the same issuer may be reused only when it remains
 * healthy and its journal state is re-read.</p>
 */
final class PaperServerAuthorityIssueCoordinator {
    private final PaperServerAuthorityLifecycle lifecycle;
    private final DurableServerAuthorityIssuer issuer;
    private boolean poisoned;

    PaperServerAuthorityIssueCoordinator(
            PaperServerAuthorityLifecycle lifecycle,
            DurableServerAuthorityIssuer issuer) {
        this.lifecycle = Objects.requireNonNull(lifecycle, "lifecycle");
        this.issuer = Objects.requireNonNull(issuer, "issuer");
    }

    synchronized Optional<DurablyIssuedServerAuthorityObservation> issue(
            UUID carryingPlayerId,
            ServerAuthorityObservationCodec.ObservationRequest request)
            throws AuthorityProtocolException, IOException {
        Objects.requireNonNull(carryingPlayerId, "carryingPlayerId");
        Objects.requireNonNull(request, "request");
        ensureHealthy();

        Optional<PaperServerAuthorityLifecycle.IssuanceLease> prepared =
                lifecycle.nextIssuance(carryingPlayerId);
        if (prepared.isEmpty()) {
            return Optional.empty();
        }
        PaperServerAuthorityLifecycle.IssuanceLease lease = prepared.orElseThrow();
        if (!lease.matchesRequest(carryingPlayerId, request)) {
            abortOrPoison(carryingPlayerId, lease);
            throw new AuthorityProtocolException(
                    "authority observation request does not match the prepared lifecycle");
        }

        final DurablyIssuedServerAuthorityObservation durableObservation;
        try {
            durableObservation = issuer.issue(
                    lease.grant(), lease.observationSequence(), request);
        } catch (AuthoritySequenceMismatchException exception) {
            // The lease was recovered from an older durable sequence. Drop it; accepting a fresh
            // typed recovery is required before this player can prepare another issuance.
            lifecycle.remove(carryingPlayerId);
            throw exception;
        } catch (AuthorityProtocolException exception) {
            abortOrPoison(carryingPlayerId, lease);
            throw exception;
        } catch (IOException exception) {
            // The journal outcome may be uncertain. Do not leave a retryable in-memory lease.
            poisoned = true;
            lifecycle.remove(carryingPlayerId);
            throw exception;
        } catch (RuntimeException exception) {
            // Runtime failures from the issuer do not prove that the append never happened.
            // Treat them like uncertain I/O rather than making the lease retryable.
            poisoned = true;
            lifecycle.remove(carryingPlayerId);
            throw exception;
        }

        if (!lifecycle.commitIssuance(carryingPlayerId, lease, durableObservation)) {
            // The journal has advanced. Abort/retry would permit sequence confusion.
            poisoned = true;
            lifecycle.remove(carryingPlayerId);
            throw new IOException(
                    "durable authority issuance could not be committed to the lifecycle");
        }
        return Optional.of(durableObservation);
    }

    synchronized boolean poisoned() {
        return poisoned;
    }

    private void ensureHealthy() throws IOException {
        if (poisoned) {
            throw new IOException("Paper authority issue coordinator is poisoned");
        }
    }

    private void abortOrPoison(
            UUID carryingPlayerId,
            PaperServerAuthorityLifecycle.IssuanceLease lease) throws IOException {
        if (!lifecycle.abortIssuance(carryingPlayerId, lease)) {
            poisoned = true;
            lifecycle.remove(carryingPlayerId);
            throw new IOException("authority issuance lease could not be aborted");
        }
    }
}
