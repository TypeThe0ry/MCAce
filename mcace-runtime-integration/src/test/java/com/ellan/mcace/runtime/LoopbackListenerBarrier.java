package com.ellan.mcace.runtime;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.time.Duration;
import java.util.function.BooleanSupplier;

/** Test-only startup barrier; persisted files and buffered logs are not readiness. */
final class LoopbackListenerBarrier {
    private LoopbackListenerBarrier() { }

    static void await(int port, Duration timeout, BooleanSupplier processAlive)
            throws IOException, InterruptedException {
        if (timeout.isNegative() || timeout.isZero()) {
            throw new IllegalArgumentException("positive startup timeout required");
        }
        long started = System.nanoTime();
        long budget = timeout.toNanos();
        while (System.nanoTime() - started < budget) {
            if (!processAlive.getAsBoolean()) {
                throw new IOException("proxy exited before listener " + port);
            }
            long remaining = budget - (System.nanoTime() - started);
            if (remaining <= 0) break;
            try (Socket socket = new Socket()) {
                int connectMillis = (int) Math.max(1, Math.min(250,
                        Duration.ofNanos(remaining).toMillis()));
                socket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), connectMillis);
                if (!processAlive.getAsBoolean()) {
                    throw new IOException("proxy exited during listener probe " + port);
                }
                return;
            } catch (IOException failure) {
                if (!processAlive.getAsBoolean()) throw failure;
            }
            remaining = budget - (System.nanoTime() - started);
            if (remaining > 0) Thread.sleep(Math.min(250,
                    Math.max(1, Duration.ofNanos(remaining).toMillis())));
        }
        throw new IOException("proxy did not bind loopback listener " + port);
    }
}
