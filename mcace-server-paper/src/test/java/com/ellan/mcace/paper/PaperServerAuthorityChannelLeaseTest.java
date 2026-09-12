package com.ellan.mcace.paper;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import org.junit.jupiter.api.Test;

final class PaperServerAuthorityChannelLeaseTest {
    @Test
    void incomingRegistrationFailureClosesRuntimeWithoutPublishingAChannel() {
        TestResource resource = new TestResource();
        TestChannels channels = new TestChannels();
        channels.failIncoming = true;

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> PaperServerAuthorityChannelLease.open(() -> resource, channels));

        assertEquals("incoming failed", failure.getMessage());
        assertTrue(resource.closed);
        assertFalse(channels.incomingRegistered);
        assertFalse(channels.outgoingRegistered);
        assertEquals(1, channels.incomingUnregisters,
                "an attempted registration is always compensated because the platform may mutate then throw");
        assertEquals(0, channels.outgoingUnregisters);
    }

    @Test
    void incomingMutationThenThrowIsCompensatedExactlyOnce() {
        TestResource resource = new TestResource();
        TestChannels channels = new TestChannels();
        channels.failIncomingAfterMutation = true;

        assertThrows(IllegalStateException.class,
                () -> PaperServerAuthorityChannelLease.open(() -> resource, channels));

        assertTrue(resource.closed);
        assertFalse(channels.incomingRegistered);
        assertEquals(1, channels.incomingUnregisters);
        assertEquals("register-in,unregister-in,close", channels.trace);
    }

    @Test
    void outgoingMutationThenThrowIsCompensatedBeforeIncomingExactlyOnce() {
        TestResource resource = new TestResource();
        TestChannels channels = new TestChannels();
        channels.failOutgoingAfterMutation = true;

        assertThrows(IllegalStateException.class,
                () -> PaperServerAuthorityChannelLease.open(() -> resource, channels));

        assertTrue(resource.closed);
        assertFalse(channels.incomingRegistered);
        assertFalse(channels.outgoingRegistered);
        assertEquals(1, channels.incomingUnregisters);
        assertEquals(1, channels.outgoingUnregisters);
        assertEquals("register-in,register-out,unregister-out,unregister-in,close", channels.trace);
    }

    @Test
    void outgoingRegistrationFailureRollsBackIncomingAndClosesRuntime() {
        TestResource resource = new TestResource();
        TestChannels channels = new TestChannels();
        channels.failOutgoing = true;

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> PaperServerAuthorityChannelLease.open(() -> resource, channels));

        assertEquals("outgoing failed", failure.getMessage());
        assertTrue(resource.closed);
        assertFalse(channels.incomingRegistered);
        assertFalse(channels.outgoingRegistered);
        assertEquals(1, channels.incomingUnregisters);
        assertEquals(1, channels.outgoingUnregisters,
                "an attempted outgoing registration is always compensated");
    }

    @Test
    void successfulLeasePublishesOnlyAfterBothRegistrationsAndClosesInReverseOrder()
            throws Exception {
        TestResource resource = new TestResource();
        TestChannels channels = new TestChannels();

        PaperServerAuthorityChannelLease<TestResource> lease =
                PaperServerAuthorityChannelLease.open(() -> resource, channels);

        assertSame(resource, lease.resource());
        assertTrue(channels.incomingRegistered);
        assertTrue(channels.outgoingRegistered);
        lease.close();
        assertTrue(resource.closed);
        assertFalse(channels.incomingRegistered);
        assertFalse(channels.outgoingRegistered);
        assertEquals("register-in,register-out,unregister-out,unregister-in,close", channels.trace);
        assertDoesNotThrow(lease::close);
        assertThrows(IllegalStateException.class, lease::resource);
    }

    @Test
    void rollbackPreservesOriginalFailureAndSuppressesCleanupFailures() {
        TestResource resource = new TestResource();
        resource.failClose = true;
        TestChannels channels = new TestChannels();
        channels.failOutgoing = true;
        channels.failIncomingUnregister = true;

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> PaperServerAuthorityChannelLease.open(() -> resource, channels));

        assertEquals("outgoing failed", failure.getMessage());
        assertEquals(2, failure.getSuppressed().length);
        assertEquals("incoming unregister failed", failure.getSuppressed()[0].getMessage());
        assertEquals("close failed", failure.getSuppressed()[1].getMessage());
    }

    private static final class TestResource implements java.io.Closeable {
        private boolean closed;
        private boolean failClose;
        private TestChannels channels;

        @Override
        public void close() throws IOException {
            closed = true;
            if (channels != null) channels.append("close");
            if (failClose) throw new IOException("close failed");
        }
    }

    private static final class TestChannels
            implements PaperServerAuthorityChannelLease.ChannelOperations<TestResource> {
        private boolean incomingRegistered;
        private boolean outgoingRegistered;
        private boolean failIncoming;
        private boolean failOutgoing;
        private boolean failIncomingAfterMutation;
        private boolean failOutgoingAfterMutation;
        private boolean failIncomingUnregister;
        private int incomingUnregisters;
        private int outgoingUnregisters;
        private String trace = "";

        @Override
        public void registerIncoming(TestResource resource) {
            resource.channels = this;
            if (failIncoming) throw new IllegalStateException("incoming failed");
            incomingRegistered = true;
            append("register-in");
            if (failIncomingAfterMutation) throw new IllegalStateException("incoming failed after mutation");
        }

        @Override
        public void unregisterIncoming(TestResource resource) {
            incomingUnregisters++;
            incomingRegistered = false;
            append("unregister-in");
            if (failIncomingUnregister) throw new IllegalStateException("incoming unregister failed");
        }

        @Override
        public void registerOutgoing() {
            if (failOutgoing) throw new IllegalStateException("outgoing failed");
            outgoingRegistered = true;
            append("register-out");
            if (failOutgoingAfterMutation) throw new IllegalStateException("outgoing failed after mutation");
        }

        @Override
        public void unregisterOutgoing() {
            outgoingUnregisters++;
            outgoingRegistered = false;
            append("unregister-out");
        }

        private void append(String value) {
            trace = trace.isEmpty() ? value : trace + "," + value;
        }
    }
}
