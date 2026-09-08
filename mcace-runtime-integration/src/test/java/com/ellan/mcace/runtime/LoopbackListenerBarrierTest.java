package com.ellan.mcace.runtime;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

@Timeout(5)
final class LoopbackListenerBarrierTest {
    @Test
    void acceptsLiveListener() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            LoopbackListenerBarrier.await(listener.getLocalPort(), Duration.ofSeconds(1), () -> true);
        }
    }

    @Test
    void rejectsExitedProcessEvenWhenPortIsListening() throws Exception {
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            IOException failure = assertThrows(IOException.class, () ->
                    LoopbackListenerBarrier.await(listener.getLocalPort(), Duration.ofSeconds(1), () -> false));
            assertTrue(failure.getMessage().contains("exited before listener"));
        }
    }

    @Test
    void rechecksProcessAfterConnection() throws Exception {
        AtomicInteger checks = new AtomicInteger();
        try (ServerSocket listener = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            assertThrows(IOException.class, () -> LoopbackListenerBarrier.await(
                    listener.getLocalPort(), Duration.ofSeconds(1), () -> checks.incrementAndGet() == 1));
        }
    }

    @Test
    void timesOutWithoutListener() throws Exception {
        int port;
        try (ServerSocket reservation = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            port = reservation.getLocalPort();
        }
        IOException failure = assertThrows(IOException.class, () ->
                LoopbackListenerBarrier.await(port, Duration.ofMillis(100), () -> true));
        assertTrue(failure.getMessage().contains("did not bind loopback listener"));
    }
}
