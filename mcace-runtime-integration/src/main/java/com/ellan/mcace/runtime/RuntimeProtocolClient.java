package com.ellan.mcace.runtime;

import com.ellan.mcace.client.integrity.ClientIntegrityBundle;
import com.ellan.mcace.client.integrity.ScopeIntegrityManifest;
import com.ellan.mcace.client.policy.VerifiedPolicyCache;
import com.ellan.mcace.client.session.ClientHandshakeEngine;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.generated.AuthResult;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.protocol.integrity.IntegrityDigests;
import com.google.protobuf.ByteString;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

final class RuntimeProtocolClient {
    void run(
            int port,
            PublicKey serverRoot,
            RuntimeScenario scenario,
            String label,
            UUID connectionPlayer,
            Path cacheDirectory) throws Exception {
        try (Socket socket = new Socket(InetAddress.getLoopbackAddress(), port);
             DataInputStream input = new DataInputStream(socket.getInputStream());
             DataOutputStream output = new DataOutputStream(socket.getOutputStream())) {
            socket.setSoTimeout(4_000);
            RuntimeWire.write(output, (connectionPlayer + "|" + label).getBytes(StandardCharsets.UTF_8));
            byte[] serverHello = RuntimeWire.read(input);
            PublicKey pinned = scenario == RuntimeScenario.UNPINNED_SERVER
                    ? Ed25519Keys.generate(new SecureRandom()).getPublic()
                    : serverRoot;
            UUID assertedPlayer = scenario == RuntimeScenario.WRONG_PLAYER_UUID
                    ? UUID.randomUUID()
                    : connectionPlayer;
            String build = scenario == RuntimeScenario.INCOMPATIBLE_BUILD
                    ? "runtime-incompatible"
                    : "runtime-good";
            ClientHandshakeEngine engine = new ClientHandshakeEngine(
                    assertedPlayer,
                    "runtime-integration",
                    "1.21.1",
                    build,
                    LoaderType.FABRIC,
                    pinned,
                    Clock.systemUTC(),
                    new SecureRandom());
            try {
                engine.prepareServerHello(
                        serverHello,
                        "127.0.0.1:" + port,
                        new VerifiedPolicyCache(cacheDirectory, Clock.systemUTC()));
            } catch (EnvelopeException expected) {
                if (scenario != RuntimeScenario.UNPINNED_SERVER
                        && scenario != RuntimeScenario.INCOMPATIBLE_BUILD) {
                    throw expected;
                }
                Thread.sleep(4_000);
                return;
            }
            List<byte[]> frames = engine.createAuthentication(emptyBundle());
            switch (scenario) {
                case GOOD -> {
                    RuntimeWire.write(output, frames.get(0));
                    RuntimeWire.write(output, frames.get(1));
                    AuthResult result = engine.receiveAuthResult(RuntimeWire.read(input));
                    if (!result.getAccepted()) throw new IllegalStateException("known-good client was rejected");
                }
                case REPLAY_CLIENT_HELLO -> {
                    RuntimeWire.write(output, frames.get(0));
                    RuntimeWire.write(output, frames.get(0));
                }
                case FORGED_CLIENT_SIGNATURE -> RuntimeWire.write(output, forged(frames.get(0)));
                case OVERSIZED_FRAME -> {
                    output.writeInt(RuntimeWire.MAX_FRAME_BYTES + 1);
                    output.flush();
                }
                case TRUNCATED_FRAME -> {
                    output.writeInt(128);
                    output.write(new byte[] {1, 2, 3});
                    output.flush();
                    socket.shutdownOutput();
                }
                case MALFORMED_PROTOBUF -> RuntimeWire.write(output, new byte[] {8, 1, 18, 2, 99, 100});
                case OUT_OF_ORDER_AUTH -> RuntimeWire.write(output, frames.get(1));
                case WRONG_PLAYER_UUID -> {
                    RuntimeWire.write(output, frames.get(0));
                    RuntimeWire.write(output, frames.get(1));
                }
                case UNPINNED_SERVER, INCOMPATIBLE_BUILD ->
                        throw new IllegalStateException("preflight rejection scenario unexpectedly passed");
            }
            if (scenario != RuntimeScenario.GOOD) Thread.sleep(200);
        }
    }

    private static byte[] forged(byte[] encoded) throws Exception {
        SignedEnvelope envelope = SignedEnvelope.parseFrom(encoded);
        byte[] signature = envelope.getSignature().toByteArray();
        signature[0] ^= 1;
        return envelope.toBuilder().setSignature(ByteString.copyFrom(signature)).build().toByteArray();
    }

    private static ClientIntegrityBundle emptyBundle() throws Exception {
        return ClientIntegrityBundle.of(List.of(new ScopeIntegrityManifest(
                "mods", "mods", true, Instant.now(), List.of(), IntegrityDigests.scopeRoot(List.of()))));
    }

    static PublicKey decodeRoot(String encoded) throws Exception {
        return Ed25519Keys.decodePublic(Base64.getDecoder().decode(encoded));
    }
}
