package com.ellan.mcace.runtime;

import com.ellan.mcace.core.api.InMemoryMCAceApi;
import com.ellan.mcace.core.risk.RiskEngine;
import com.ellan.mcace.core.risk.RiskPolicy;
import com.ellan.mcace.core.session.HandshakeAction;
import com.ellan.mcace.core.session.ServerHandshakeCoordinator;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

final class RuntimeProtocolServer {
    private static final Duration HANDSHAKE_TIMEOUT = Duration.ofSeconds(3);
    private static final int SOCKET_READ_TIMEOUT_MILLIS = 3_500;
    private final RuntimeFixture fixture;

    RuntimeProtocolServer(RuntimeFixture fixture) {
        this.fixture = fixture;
    }

    void run(int expectedConnections) throws Exception {
        CountDownLatch completed = new CountDownLatch(expectedConnections);
        try (ServerSocket listener = new ServerSocket(0, expectedConnections, InetAddress.getLoopbackAddress());
             var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            listener.setSoTimeout(15_000);
            System.out.println("READY|" + listener.getLocalPort() + "|"
                    + Base64.getEncoder().encodeToString(fixture.serverIdentity().getPublic().getEncoded()));
            System.out.flush();
            for (int index = 0; index < expectedConnections; index++) {
                Socket socket = listener.accept();
                executor.submit(() -> {
                    try {
                        handle(socket);
                    } catch (Exception exception) {
                        synchronized (System.out) {
                            System.out.println("SERVER_ERROR|" + exception.getClass().getSimpleName() + "|"
                                    + sanitize(exception.getMessage()));
                            System.out.flush();
                        }
                    } finally {
                        completed.countDown();
                    }
                });
            }
            if (!completed.await(20, TimeUnit.SECONDS)) {
                throw new IOException("runtime clients did not finish within twenty seconds");
            }
        }
    }

    private void handle(Socket socket) throws Exception {
        try (socket;
             DataInputStream input = new DataInputStream(socket.getInputStream());
             DataOutputStream output = new DataOutputStream(socket.getOutputStream())) {
            socket.setSoTimeout(SOCKET_READ_TIMEOUT_MILLIS);
            byte[] connectFrame = RuntimeWire.read(input);
            String connect = new String(connectFrame, StandardCharsets.UTF_8);
            String[] identity = connect.split("\\|", -1);
            if (identity.length != 2) throw new IOException("malformed runtime identity frame");
            UUID playerId = UUID.fromString(identity[0]);
            String label = identity[1];
            if (!label.matches("[A-Z0-9_]{1,64}")) throw new IOException("invalid runtime scenario label");
            trace(label, "C2S_CONNECT", 0, connectFrame);
            InMemoryMCAceApi api = new InMemoryMCAceApi();
            ServerHandshakeCoordinator coordinator = new ServerHandshakeCoordinator(
                    Clock.systemUTC(),
                    new SecureRandom(),
                    fixture.serverIdentity(),
                    new RiskEngine(RiskPolicy.defaults()),
                    api,
                    HANDSHAKE_TIMEOUT,
                    fixture::policy);
            byte[] serverHello = coordinator.begin(playerId);
            trace(label, "S2C_ENVELOPE", 0, serverHello);
            RuntimeWire.write(output, serverHello);
            int inboundSequence = 0;
            int outboundSequence = 1;
            while (true) {
                try {
                    byte[] frame = RuntimeWire.read(input);
                    trace(label, "C2S_ENVELOPE", inboundSequence++, frame);
                    HandshakeAction action = coordinator.receive(playerId, frame);
                    for (byte[] outbound : action.outboundFrames()) {
                        trace(label, "S2C_ENVELOPE", outboundSequence++, outbound);
                        RuntimeWire.write(output, outbound);
                    }
                    if (action.snapshot().isPresent()) {
                        emit(label, action.snapshot().orElseThrow(), action.protocolViolation());
                        return;
                    }
                } catch (SocketTimeoutException exception) {
                    traceEvent(label, "READ_TIMEOUT");
                    PlayerSecuritySnapshot snapshot = coordinator.expireTimedOut().stream()
                            .findFirst()
                            .orElseThrow(() -> new IOException("session did not expire", exception));
                    emit(label, snapshot, false);
                    return;
                } catch (IOException exception) {
                    traceEvent(label, "TRANSPORT_REJECT_" + exception.getClass().getSimpleName());
                    HandshakeAction action = coordinator.receive(playerId, new byte[0]);
                    emit(label, action.snapshot().orElseThrow(), true);
                    return;
                }
            }
        }
    }

    private static void emit(String label, PlayerSecuritySnapshot snapshot, boolean violation) {
        synchronized (System.out) {
            System.out.println("RESULT|" + label + "|" + snapshot.admissionStatus() + "|"
                    + snapshot.trustLevel() + "|" + snapshot.riskScore() + "|" + violation);
            System.out.flush();
        }
    }

    private static void trace(String label, String direction, int sequence, byte[] frame) {
        synchronized (System.out) {
            System.out.println("TRACE|" + label + "|" + direction + "|" + sequence + "|"
                    + frame.length + "|" + sha256Hex(frame));
            System.out.flush();
        }
    }

    private static void traceEvent(String label, String event) {
        synchronized (System.out) {
            System.out.println("TRACE_EVENT|" + label + "|" + event);
            System.out.flush();
        }
    }

    private static String sha256Hex(byte[] frame) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(frame));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private static String sanitize(String message) {
        return message == null ? "none" : message.replace('|', '_').replace('\n', ' ');
    }
}
