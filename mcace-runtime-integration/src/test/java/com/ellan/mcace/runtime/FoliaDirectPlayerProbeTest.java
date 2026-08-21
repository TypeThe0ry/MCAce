package com.ellan.mcace.runtime;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.admission.SignedAdmissionSnapshotCodec;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import com.ellan.mcace.sdk.RiskBand;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Test-only direct Folia peer. It implements only bounded offline login/configuration and one
 * signed C2S admission payload; it is not a Minecraft client product. The optional
 * {@code mcace.admission-probe.mode} only selects bounded, local admission frames for the
 * Paper/Folia hostile-admission gate. It never scans a host, contacts an external system, or
 * records a key, player identity, session identifier, or payload.
 */
final class FoliaDirectPlayerProbeTest {
    private static final int MAX_PACKET_BYTES = 2 * 1024 * 1024;
    private static final String PLAYER_NAME = "MCAceFoliaProbe";
    private static final UUID PLAYER_ID = UUID.nameUUIDFromBytes(
            ("OfflinePlayer:" + PLAYER_NAME).getBytes(StandardCharsets.UTF_8));

    @Test
    @Timeout(60)
    void directFoliaPlayerReachesEntityScheduledAdmissionConsumer() throws Exception {
        String portValue = System.getProperty("mcace.folia.player-probe.port", "").trim();
        Assumptions.assumeTrue(!portValue.isEmpty(), "external Folia probe is opt-in");
        RuntimeProcessAssets.BackendAssets runtimeAssets =
                RuntimeProcessAssets.backendFromSystemProperties("FOLIA");
        AdmissionProbeMode mode = AdmissionProbeMode.parse(
                System.getProperty("mcace.admission-probe.mode", "PINNED_BASELINE"));
        ProbeReport report = new Peer(
                System.getProperty("mcace.folia.player-probe.host", "127.0.0.1"),
                Integer.parseInt(portValue),
                runtimeAssets.wireProfile(),
                privateKey(Path.of(required("mcace.folia.player-probe.private-key-path"))),
                Long.parseLong(System.getProperty("mcace.folia.player-probe.hold-millis", "4500")),
                mode)
                .run();
        Path reportPath = Path.of(required("mcace.folia.player-probe.report-path"));
        Files.createDirectories(reportPath.getParent());
        Files.writeString(reportPath, report.toJson(), StandardCharsets.UTF_8);
        System.out.println("FOLIA_DIRECT_PLAYER_PROBE_REPORT|" + reportPath);
        assertTrue(report.loginSuccess(), report.toJson());
        assertTrue(report.configurationFinished(), report.toJson());
        assertTrue(report.payloadDispatchCompleted(), report.toJson());
        assertEquals(mode.permittedSnapshotExpected(), report.permittedSnapshotSent(), report.toJson());
        assertEquals(mode.hostilePayloadExpected(), report.hostilePayloadSent(), report.toJson());
    }

    private static String required(String key) {
        String value = System.getProperty(key, "").trim();
        if (value.isEmpty()) throw new IllegalArgumentException("missing system property " + key);
        return value;
    }

    private static PrivateKey privateKey(Path path) throws Exception {
        byte[] encoded = Base64.getDecoder().decode(Files.readString(path, StandardCharsets.UTF_8).trim());
        return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(encoded));
    }

    private static final class Peer {
        private final String host;
        private final int port;
        private final MinecraftWireProfile wireProfile;
        private final PrivateKey signingKey;
        private final long holdMillis;
        private final AdmissionProbeMode mode;
        private int compressionThreshold = -1;
        private State state = State.LOGIN;
        private boolean loginSuccess;
        private boolean configurationFinished;
        private boolean payloadDispatchCompleted;
        private boolean permittedSnapshotSent;
        private boolean hostilePayloadSent;

        private Peer(
                String host,
                int port,
                MinecraftWireProfile wireProfile,
                PrivateKey signingKey,
                long holdMillis,
                AdmissionProbeMode mode) {
            this.host = host;
            this.port = port;
            this.wireProfile = wireProfile;
            this.signingKey = signingKey;
            this.holdMillis = Math.max(3_500L, holdMillis);
            this.mode = mode;
        }

        private ProbeReport run() throws Exception {
            try (Socket socket = new Socket(InetAddress.getByName(host), port)) {
                socket.setSoTimeout(10_000);
                DataInputStream input = new DataInputStream(socket.getInputStream());
                DataOutputStream output = new DataOutputStream(socket.getOutputStream());
                send(output, 0x00, handshake());
                send(output, 0x00, loginStart());
                long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(30);
                while (System.nanoTime() < deadline && !payloadDispatchCompleted) {
                    Packet packet = read(input);
                    if (state == State.LOGIN) {
                        handleLogin(output, packet);
                    } else if (state == State.CONFIGURATION) {
                        handleConfiguration(output, packet);
                    }
                }
                if (payloadDispatchCompleted) Thread.sleep(holdMillis);
            } catch (EOFException exception) {
                // The report exposes the failed state; tests do not treat a disconnect as success.
            }
            return new ProbeReport(
                    wireProfile.protocolVersion(),
                    loginSuccess,
                    configurationFinished,
                    payloadDispatchCompleted,
                    permittedSnapshotSent,
                    hostilePayloadSent,
                    mode);
        }

        private void handleLogin(DataOutputStream output, Packet packet) throws Exception {
            if (packet.id() == 0x03) {
                compressionThreshold = readVarInt(new ByteArrayInputStream(packet.payload()));
            } else if (packet.id() == 0x02) {
                loginSuccess = true;
                send(output, 0x03, new byte[0]);
                state = State.CONFIGURATION;
                send(output, wireProfile.configuration().serverboundClientInformation(),
                        clientInformation(wireProfile));
                sendCustomPayload(output, "minecraft:register", "mcace:admission".getBytes(StandardCharsets.UTF_8));
            } else if (packet.id() == 0x04) {
                DataInputStream request = new DataInputStream(new ByteArrayInputStream(packet.payload()));
                send(output, 0x02, concat(varInt(readVarInt(request)), new byte[] {0}));
            } else if (packet.id() == 0x01) {
                throw new IOException("offline test peer cannot satisfy encryption request");
            }
        }

        private void handleConfiguration(DataOutputStream output, Packet packet) throws Exception {
            MinecraftWireProfile.ConfigurationPackets packets = wireProfile.configuration();
            if (packet.id() == packets.clientboundFinish()) {
                send(output, packets.serverboundFinish(), new byte[0]);
                configurationFinished = true;
                state = State.PLAY;
                sendAdmission(output);
            } else if (packet.id() == packets.clientboundKeepAlive()) {
                send(output, packets.serverboundKeepAlive(), packet.payload());
            } else if (packet.id() == packets.clientboundPing()) {
                send(output, packets.serverboundPong(), packet.payload());
            } else if (packet.id() == packets.clientboundSelectKnownPacks()) {
                send(output, packets.serverboundSelectKnownPacks(), varInt(0));
            } else if (packet.id() == packets.clientboundCookieRequest()) {
                DataInputStream request = new DataInputStream(new ByteArrayInputStream(packet.payload()));
                send(output, packets.serverboundCookieResponse(),
                        concat(string(readString(request)), new byte[] {0}));
            }
        }

        private void sendAdmission(DataOutputStream output) throws Exception {
            switch (mode) {
                case PINNED_BASELINE -> sendPermittedSnapshot(output, signingKey, PLAYER_ID, 1L);
                case UNPINNED_SIGNER -> {
                    KeyPair unpinned = Ed25519Keys.generate(new SecureRandom());
                    sendHostileSnapshot(output, unpinned.getPrivate(), PLAYER_ID, 1L);
                }
                case WRONG_CARRIER_UUID -> sendHostileSnapshot(
                        output,
                        signingKey,
                        UUID.nameUUIDFromBytes("MCAceAdmissionWrongCarrier".getBytes(StandardCharsets.UTF_8)),
                        1L);
                case REPLAY -> {
                    byte[] permitted = signedSnapshot(signingKey, PLAYER_ID, Duration.ofSeconds(3), 1L);
                    sendCustomPayload(output, ProtocolConstants.ADMISSION_CHANNEL, permitted);
                    permittedSnapshotSent = true;
                    sendCustomPayload(output, ProtocolConstants.ADMISSION_CHANNEL, permitted);
                    hostilePayloadSent = true;
                }
                case EXPIRED -> {
                    byte[] expired = signedSnapshot(signingKey, PLAYER_ID, Duration.ofMillis(1), 1L);
                    Thread.sleep(25L);
                    sendCustomPayload(output, ProtocolConstants.ADMISSION_CHANNEL, expired);
                    hostilePayloadSent = true;
                }
                case OVERSIZE -> {
                    sendCustomPayload(output, ProtocolConstants.ADMISSION_CHANNEL,
                            new byte[ProtocolConstants.MAX_PROXY_PLUGIN_FRAME_BYTES + 1]);
                    hostilePayloadSent = true;
                }
                case WRONG_CHANNEL -> {
                    byte[] otherwiseValid = signedSnapshot(signingKey, PLAYER_ID, Duration.ofSeconds(3), 1L);
                    sendCustomPayload(output, "mcace:not-admission", otherwiseValid);
                    hostilePayloadSent = true;
                }
            }
            payloadDispatchCompleted = true;
        }

        private void sendPermittedSnapshot(
                DataOutputStream output, PrivateKey key, UUID playerId, long sequence) throws Exception {
            sendCustomPayload(output, ProtocolConstants.ADMISSION_CHANNEL,
                    signedSnapshot(key, playerId, Duration.ofSeconds(3), sequence));
            permittedSnapshotSent = true;
        }

        private void sendHostileSnapshot(
                DataOutputStream output, PrivateKey key, UUID assertedPlayerId, long sequence) throws Exception {
            sendCustomPayload(output, ProtocolConstants.ADMISSION_CHANNEL,
                    signedSnapshot(key, assertedPlayerId, Duration.ofSeconds(3), sequence));
            hostilePayloadSent = true;
        }

        private static byte[] signedSnapshot(
                PrivateKey key, UUID playerId, Duration ttl, long sequence) throws Exception {
            Instant now = Instant.now();
            PlayerSecuritySnapshot snapshot = new PlayerSecuritySnapshot(
                    playerId, TrustLevel.VERIFIED, AdmissionStatus.VERIFIED, 0, RiskBand.NORMAL,
                    "local-admission-probe", now, List.of());
            return new SignedAdmissionSnapshotCodec(Clock.systemUTC(), new SecureRandom()).sign(
                    snapshot, ttl, sequence, key);
        }

        private void sendCustomPayload(DataOutputStream output, String channel, byte[] data) throws IOException {
            int packetId = state == State.CONFIGURATION
                    ? wireProfile.configuration().serverboundCustomPayload()
                    : wireProfile.play().serverboundCustomPayload();
            send(output, packetId, concat(string(channel), data));
        }

        private Packet read(DataInputStream input) throws IOException, DataFormatException {
            int frameLength = readVarInt(input);
            if (frameLength <= 0 || frameLength > MAX_PACKET_BYTES) throw new IOException("invalid packet length");
            byte[] frame = input.readNBytes(frameLength);
            if (frame.length != frameLength) throw new EOFException("truncated packet");
            DataInputStream framed = new DataInputStream(new ByteArrayInputStream(frame));
            byte[] packetData;
            if (compressionThreshold >= 0) {
                int uncompressedLength = readVarInt(framed);
                byte[] remaining = framed.readAllBytes();
                packetData = uncompressedLength == 0 ? remaining : inflate(remaining, uncompressedLength);
            } else {
                packetData = frame;
            }
            DataInputStream packet = new DataInputStream(new ByteArrayInputStream(packetData));
            return new Packet(readVarInt(packet), packet.readAllBytes());
        }

        private void send(DataOutputStream output, int id, byte[] payload) throws IOException {
            byte[] packet = concat(varInt(id), payload);
            byte[] framed = compressionThreshold < 0 ? packet : concat(varInt(0), packet);
            output.write(varInt(framed.length));
            output.write(framed);
            output.flush();
        }

        private byte[] handshake() throws IOException {
            return concat(varInt(wireProfile.protocolVersion()), string(host), shortBytes(port), varInt(2));
        }
    }

    private enum State { LOGIN, CONFIGURATION, PLAY }
    private record Packet(int id, byte[] payload) { }
    private enum AdmissionProbeMode {
        PINNED_BASELINE(true, false),
        UNPINNED_SIGNER(false, true),
        WRONG_CARRIER_UUID(false, true),
        REPLAY(true, true),
        EXPIRED(false, true),
        OVERSIZE(false, true),
        WRONG_CHANNEL(false, true);

        private final boolean permittedSnapshotExpected;
        private final boolean hostilePayloadExpected;

        AdmissionProbeMode(boolean permittedSnapshotExpected, boolean hostilePayloadExpected) {
            this.permittedSnapshotExpected = permittedSnapshotExpected;
            this.hostilePayloadExpected = hostilePayloadExpected;
        }

        private static AdmissionProbeMode parse(String value) {
            try {
                return valueOf(value.trim().toUpperCase(java.util.Locale.ROOT));
            } catch (IllegalArgumentException exception) {
                throw new IllegalArgumentException("unknown local admission-probe mode", exception);
            }
        }

        private boolean permittedSnapshotExpected() {
            return permittedSnapshotExpected;
        }

        private boolean hostilePayloadExpected() {
            return hostilePayloadExpected;
        }
    }

    private record ProbeReport(
            int protocol,
            boolean loginSuccess,
            boolean configurationFinished,
            boolean payloadDispatchCompleted,
            boolean permittedSnapshotSent,
            boolean hostilePayloadSent,
            AdmissionProbeMode mode) {
        private String toJson() {
            return "{\"schema\":2,\"protocol\":" + protocol
                    + ",\"login_success\":" + loginSuccess
                    + ",\"configuration_finished\":" + configurationFinished
                    + ",\"payload_dispatch_completed\":" + payloadDispatchCompleted
                    + ",\"permitted_snapshot_sent\":" + permittedSnapshotSent
                    + ",\"hostile_payload_sent\":" + hostilePayloadSent
                    + ",\"mode\":\"" + mode.name() + "\"}";
        }
    }

    private static byte[] clientInformation(MinecraftWireProfile profile) throws IOException {
        byte[] legacy = concat(
                string("en_us"),
                new byte[] {8},
                varInt(0),
                new byte[] {1, 0},
                varInt(1),
                new byte[] {0, 1});
        // 1.21.2 added the final particle-status VarInt. Omitting it makes Folia reject the
        // configuration packet before a Player exists, so the entity scheduler is never reached.
        return profile.clientInformationIncludesParticleStatus()
                ? concat(legacy, varInt(0)) : legacy;
    }

    private static byte[] loginStart() throws IOException {
        return concat(string(PLAYER_NAME), longBytes(PLAYER_ID.getMostSignificantBits()), longBytes(PLAYER_ID.getLeastSignificantBits()));
    }

    private static byte[] inflate(byte[] compressed, int expectedLength) throws DataFormatException, IOException {
        if (expectedLength <= 0 || expectedLength > MAX_PACKET_BYTES) throw new IOException("invalid uncompressed packet length");
        Inflater inflater = new Inflater();
        inflater.setInput(compressed);
        byte[] output = new byte[expectedLength];
        int length = inflater.inflate(output);
        boolean complete = inflater.finished() && length == expectedLength;
        inflater.end();
        if (!complete) throw new IOException("compressed packet did not reach declared length");
        return output;
    }

    private static byte[] string(String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        return concat(varInt(bytes.length), bytes);
    }

    private static String readString(DataInputStream input) throws IOException {
        int length = readVarInt(input);
        if (length < 0 || length > 32_767) throw new IOException("invalid string length");
        return new String(input.readNBytes(length), StandardCharsets.UTF_8);
    }

    private static byte[] varInt(int value) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        while ((value & 0xffffff80) != 0) { output.write((value & 0x7f) | 0x80); value >>>= 7; }
        output.write(value);
        return output.toByteArray();
    }

    private static int readVarInt(java.io.InputStream input) throws IOException {
        int value = 0;
        for (int position = 0; position < 5; position++) {
            int current = input.read();
            if (current < 0) throw new EOFException("truncated VarInt");
            value |= (current & 0x7f) << (position * 7);
            if ((current & 0x80) == 0) return value;
        }
        throw new IOException("VarInt is too large");
    }

    private static byte[] longBytes(long value) {
        return new byte[] {(byte) (value >>> 56), (byte) (value >>> 48), (byte) (value >>> 40), (byte) (value >>> 32),
                (byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value};
    }

    private static byte[] shortBytes(int value) { return new byte[] {(byte) (value >>> 8), (byte) value}; }

    private static byte[] concat(byte[]... parts) {
        int length = 0; for (byte[] part : parts) length += part.length;
        byte[] result = new byte[length]; int offset = 0;
        for (byte[] part : parts) { System.arraycopy(part, 0, result, offset, part.length); offset += part.length; }
        return result;
    }
}
