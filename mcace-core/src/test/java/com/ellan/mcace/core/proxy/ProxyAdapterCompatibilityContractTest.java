package com.ellan.mcace.core.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.admission.SignedAdmissionSnapshotCodec;
import com.ellan.mcace.core.api.InMemoryMCAceApi;
import com.ellan.mcace.core.risk.RiskEngine;
import com.ellan.mcace.core.risk.RiskPolicy;
import com.ellan.mcace.core.session.ServerHandshakeCoordinator;
import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.generated.EnvelopeHeader;
import com.ellan.mcace.protocol.generated.PacketType;
import com.ellan.mcace.protocol.generated.SignedEnvelope;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.PlayerSecuritySnapshot;
import com.ellan.mcace.sdk.RiskBand;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** Shared assertions which every proxy adapter reaches through its thin transport boundary. */
final class ProxyAdapterCompatibilityContractTest {
    private static final Clock CLOCK = Clock.fixed(Instant.parse("2026-08-09T00:00:00Z"), ZoneOffset.UTC);

    @Test
    void playerOnlyGateConsumesAuthorityFramesAndClassifiesClientTransport() {
        assertEquals(ProxyAdapterTransportContract.InboundDecision.CLIENT_AUTH,
                ProxyAdapterTransportContract.decide(ProtocolConstants.HANDSHAKE_CHANNEL, true));
        assertEquals(ProxyAdapterTransportContract.InboundDecision.CLIENT_AUTH,
                ProxyAdapterTransportContract.decide(ProtocolConstants.PAYLOAD_CHANNEL, true));
        assertEquals(ProxyAdapterTransportContract.InboundDecision.CONSUME_ONLY,
                ProxyAdapterTransportContract.decide(ProtocolConstants.ADMISSION_CHANNEL, true));
        assertEquals(ProxyAdapterTransportContract.InboundDecision.CONSUME_ONLY,
                ProxyAdapterTransportContract.decide(ProtocolConstants.BACKEND_CONTEXT_CHANNEL, true));
        assertEquals(ProxyAdapterTransportContract.InboundDecision.BACKEND_CONTEXT,
                ProxyAdapterTransportContract.decide(ProtocolConstants.BACKEND_CONTEXT_CHANNEL, false));
        assertEquals(ProxyAdapterTransportContract.InboundDecision.CONSUME_ONLY,
                ProxyAdapterTransportContract.decide(ProtocolConstants.HANDSHAKE_CHANNEL, false));
        assertEquals(ProxyAdapterTransportContract.InboundDecision.IGNORE,
                ProxyAdapterTransportContract.decide("example:unowned", true));

        assertEquals(ProxyAdapterTransportContract.FrameKind.HANDSHAKE,
                ProxyAdapterTransportContract.classifyClientFrame(ProtocolConstants.HANDSHAKE_CHANNEL,
                        envelope(PacketType.CLIENT_HELLO)));
        assertEquals(ProxyAdapterTransportContract.FrameKind.PAYLOAD,
                ProxyAdapterTransportContract.classifyClientFrame(ProtocolConstants.PAYLOAD_CHANNEL,
                        envelope(PacketType.PAYLOAD_CHUNK)));
        assertEquals(ProxyAdapterTransportContract.FrameKind.HEARTBEAT,
                ProxyAdapterTransportContract.classifyClientFrame(ProtocolConstants.HANDSHAKE_CHANNEL,
                        envelope(PacketType.HEARTBEAT)));
        assertEquals(ProxyAdapterTransportContract.FrameKind.EVIDENCE_CLIENT,
                ProxyAdapterTransportContract.classifyClientFrame(ProtocolConstants.HANDSHAKE_CHANNEL,
                        envelope(PacketType.EVIDENCE_RESPONSE)));
        assertEquals(ProxyAdapterTransportContract.FrameKind.EVIDENCE_SERVER_ONLY,
                ProxyAdapterTransportContract.classifyClientFrame(ProtocolConstants.HANDSHAKE_CHANNEL,
                        envelope(PacketType.EVIDENCE_REQUEST)));
    }

    @Test
    void signedAdmissionOutputRequiresThePinnedProxyKeyAndDisconnectCleanupErasesState() throws Exception {
        UUID playerId = UUID.randomUUID();
        KeyPair trustedProxy = Ed25519Keys.generate(new SecureRandom());
        KeyPair otherProxy = Ed25519Keys.generate(new SecureRandom());
        PlayerSecuritySnapshot snapshot = new PlayerSecuritySnapshot(
                playerId, TrustLevel.VERIFIED, AdmissionStatus.VERIFIED, 0, RiskBand.NORMAL,
                "proxy-contract", CLOCK.instant(), List.of());
        SignedAdmissionSnapshotCodec codec = new SignedAdmissionSnapshotCodec(CLOCK, new SecureRandom());
        byte[] frame = codec.sign(snapshot, Duration.ofSeconds(15), 1L, trustedProxy.getPrivate());

        assertEquals(snapshot, codec.verify(frame, playerId, trustedProxy.getPublic(),
                new NonceReplayGuard(CLOCK, ProtocolConstants.DEFAULT_REPLAY_WINDOW)).snapshot());
        assertThrows(EnvelopeException.class, () -> codec.verify(frame, playerId, otherProxy.getPublic(),
                new NonceReplayGuard(CLOCK, ProtocolConstants.DEFAULT_REPLAY_WINDOW)));

        InMemoryMCAceApi api = new InMemoryMCAceApi();
        ServerHandshakeCoordinator coordinator = new ServerHandshakeCoordinator(
                CLOCK, new SecureRandom(), trustedProxy, new RiskEngine(RiskPolicy.defaults()), api,
                Duration.ofSeconds(30), () -> { throw new AssertionError("policy is not read during disconnect cleanup"); });
        api.publish(snapshot);
        // Both proxy adapter disconnect hooks delegate to this shared coordinator cleanup path.
        coordinator.remove(playerId);
        assertTrue(api.snapshot(playerId).isEmpty());
    }

    private static byte[] envelope(PacketType type) {
        return SignedEnvelope.newBuilder()
                .setHeader(EnvelopeHeader.newBuilder().setPacketType(type))
                .build().toByteArray();
    }
}
