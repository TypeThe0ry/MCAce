package com.ellan.mcace.bungeecord;

import com.ellan.mcace.core.evidence.EvidenceRequestRuntime;
import java.util.Objects;
import java.util.Optional;

/**
 * One-shot evidence request dispatch after the proxy has captured a physical-login binding.
 *
 * <p>This intentionally models only local dispatch initiation. Bungee's {@code sendData} has no
 * delivery acknowledgement, so a successful result never claims that the client received or
 * accepted an evidence request.</p>
 */
final class BungeeEvidenceDispatch {
    enum Status { DISPATCH_INITIATED, UNAVAILABLE, FAILED }

    record Result(Status status, Optional<String> requestId) {
        Result {
            Objects.requireNonNull(status, "status");
            Objects.requireNonNull(requestId, "requestId");
            if (status != Status.DISPATCH_INITIATED && requestId.isPresent()) {
                throw new IllegalArgumentException("only initiated dispatch exposes a request id");
            }
        }

        static Result initiated(EvidenceRequestRuntime.IssuedRequest request) {
            return new Result(Status.DISPATCH_INITIATED, Optional.of(request.request().getRequestId()));
        }

        static Result unavailable() { return new Result(Status.UNAVAILABLE, Optional.empty()); }
        static Result failed() { return new Result(Status.FAILED, Optional.empty()); }
    }

    interface Endpoint {
        /** Re-checks captured player identity, ticket, and authenticated session. */
        boolean isCurrent();

        Optional<EvidenceRequestRuntime.IssuedRequest> issue() throws Exception;

        /** Cancels the sole outstanding request for this exact still-bound coordinator session. */
        boolean cancelOutstanding();

        /** Starts local Bungee transport only; this is not a client delivery acknowledgement. */
        void send(byte[] frame);
    }

    private BungeeEvidenceDispatch() { }

    static Result dispatch(Endpoint endpoint) {
        Objects.requireNonNull(endpoint, "endpoint");
        if (!endpoint.isCurrent()) {
            return Result.unavailable();
        }
        // The adapter holds its lifecycle lock in production. Keep a second gate here as well so
        // a future endpoint implementation cannot introduce a check-then-issue replacement race.
        if (!endpoint.isCurrent()) {
            return Result.unavailable();
        }
        final EvidenceRequestRuntime.IssuedRequest issued;
        try {
            Optional<EvidenceRequestRuntime.IssuedRequest> next = endpoint.issue();
            if (next.isEmpty()) {
                return Result.unavailable();
            }
            issued = next.orElseThrow();
        } catch (Exception exception) {
            return Result.failed();
        }
        if (!endpoint.isCurrent()) {
            cancelQuietly(endpoint);
            return Result.unavailable();
        }
        try {
            endpoint.send(issued.encodedFrame());
            return Result.initiated(issued);
        } catch (RuntimeException exception) {
            cancelQuietly(endpoint);
            return Result.failed();
        }
    }

    private static void cancelQuietly(Endpoint endpoint) {
        try {
            endpoint.cancelOutstanding();
        } catch (RuntimeException ignored) {
            // Dispatch was not initiated; never turn cancellation diagnostics into a false success.
        }
    }
}
