package com.ellan.mcace.bungeecord;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.evidence.EvidenceRequestRuntime;
import com.ellan.mcace.protocol.generated.EvidenceRequest;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

final class BungeeEvidenceDispatchTest {
    @Test
    void staleCapturedPlayerCannotIssueOrSend() {
        RecordingEndpoint endpoint = new RecordingEndpoint();
        endpoint.current = false;

        assertEquals(BungeeEvidenceDispatch.Status.UNAVAILABLE, BungeeEvidenceDispatch.dispatch(endpoint).status());
        assertEquals(0, endpoint.issueCalls);
        assertEquals(0, endpoint.sendCalls);
        assertEquals(0, endpoint.cancelCalls);
    }

    @Test
    void replacementBetweenInitialGateAndIssueCannotCreateOutstandingRequest() {
        RecordingEndpoint endpoint = new RecordingEndpoint();
        endpoint.replaceAfterFirstCurrentCheck = true;

        assertEquals(BungeeEvidenceDispatch.Status.UNAVAILABLE, BungeeEvidenceDispatch.dispatch(endpoint).status());
        assertEquals(0, endpoint.issueCalls);
        assertEquals(0, endpoint.sendCalls);
        assertEquals(0, endpoint.cancelCalls);
    }

    @Test
    void replacementAfterIssueCancelsOutstandingRequestAndSendsNoFrame() {
        RecordingEndpoint endpoint = new RecordingEndpoint();
        endpoint.replaceDuringIssue = true;

        assertEquals(BungeeEvidenceDispatch.Status.UNAVAILABLE, BungeeEvidenceDispatch.dispatch(endpoint).status());
        assertEquals(1, endpoint.issueCalls);
        assertEquals(0, endpoint.sendCalls);
        assertEquals(1, endpoint.cancelCalls);
    }

    @Test
    void exactCurrentSessionIssuesAndInitiatesExactlyOneDispatch() {
        RecordingEndpoint endpoint = new RecordingEndpoint();

        BungeeEvidenceDispatch.Result result = BungeeEvidenceDispatch.dispatch(endpoint);
        assertEquals(BungeeEvidenceDispatch.Status.DISPATCH_INITIATED, result.status());
        assertEquals(Optional.of(endpoint.requestId.toString()), result.requestId());
        assertEquals(1, endpoint.issueCalls);
        assertEquals(1, endpoint.sendCalls);
        assertEquals(0, endpoint.cancelCalls);
    }

    @Test
    void sendFailureCancelsTheExactOutstandingRequestWithoutReportingDispatch() {
        RecordingEndpoint endpoint = new RecordingEndpoint();
        endpoint.sendFailure = true;

        assertEquals(BungeeEvidenceDispatch.Status.FAILED, BungeeEvidenceDispatch.dispatch(endpoint).status());
        assertEquals(1, endpoint.issueCalls);
        assertEquals(1, endpoint.sendCalls);
        assertEquals(1, endpoint.cancelCalls);
    }

    private static final class RecordingEndpoint implements BungeeEvidenceDispatch.Endpoint {
        private final UUID requestId = UUID.fromString("00000000-0000-0000-0000-000000000601");
        private boolean current = true;
        private boolean replaceAfterFirstCurrentCheck;
        private boolean replaceDuringIssue;
        private boolean sendFailure;
        private int currentChecks;
        private int issueCalls;
        private int cancelCalls;
        private int sendCalls;

        @Override public boolean isCurrent() {
            currentChecks++;
            boolean answer = current;
            if (replaceAfterFirstCurrentCheck && currentChecks == 1) current = false;
            return answer;
        }

        @Override public Optional<EvidenceRequestRuntime.IssuedRequest> issue() {
            issueCalls++;
            if (replaceDuringIssue) current = false;
            return Optional.of(new EvidenceRequestRuntime.IssuedRequest(
                    EvidenceRequest.newBuilder().setRequestId(requestId.toString()).build(), new byte[] {1, 2, 3}));
        }

        @Override public boolean cancelOutstanding() { cancelCalls++; return true; }

        @Override public void send(byte[] frame) {
            sendCalls++;
            assertTrue(frame.length > 0);
            if (sendFailure) throw new IllegalStateException("transport unavailable");
        }
    }
}
