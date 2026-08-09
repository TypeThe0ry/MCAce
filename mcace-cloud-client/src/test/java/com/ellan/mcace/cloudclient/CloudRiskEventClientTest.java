package com.ellan.mcace.cloudclient;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.core.persistence.ObservationOrigin;
import com.ellan.mcace.core.risk.RiskEventType;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

final class CloudRiskEventClientTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void authenticatesAndUploadsObservationalRiskEvent() throws Exception {
        KeyPair identity = Ed25519Keys.generate(new java.security.SecureRandom());
        byte[] challengePayload = "mcace-cloud-client-test".getBytes(StandardCharsets.UTF_8);
        AtomicReference<JsonNode> received = new AtomicReference<>();
        CountDownLatch delivered = new CountDownLatch(1);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/auth/challenges", exchange -> write(exchange, 201, Map.of(
                "challenge_id", "11111111-1111-1111-1111-111111111111",
                "signing_payload", Base64.getUrlEncoder().withoutPadding().encodeToString(challengePayload),
                "expires_at", Instant.now().plusSeconds(30).toString())));
        server.createContext("/v1/auth/tokens", exchange -> {
            JsonNode request = read(exchange);
            boolean valid = verify(identity, challengePayload, request.path("signature").asText());
            write(exchange, valid ? 201 : 401, Map.of(
                    "access_token", "test-token",
                    "expires_at", Instant.now().plusSeconds(60).toString()));
        });
        server.createContext("/v1/risk-events", exchange -> {
            if (!"Bearer test-token".equals(exchange.getRequestHeaders().getFirst("Authorization"))) {
                write(exchange, 401, Map.of("error", "unauthorized"));
                return;
            }
            received.set(read(exchange));
            write(exchange, 202, Map.of("enforcement_action", "NONE"));
            delivered.countDown();
        });
        server.start();
        URI endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
        try (CloudRiskEventClient client = new CloudRiskEventClient(
                new CloudClientConfiguration(endpoint, "paper-test", identity.getPrivate(), 8, Duration.ofSeconds(2)),
                message -> { })) {
            assertTrue(client.submit(new CloudRiskEvent(
                    UUID.randomUUID(), "", UUID.randomUUID(), RiskEventType.BEHAVIOR_HIGH_RISK,
                    "grim-adapter", ObservationOrigin.SERVER_CONFIRMED, false, Instant.now(),
                    Map.of("schema", "mcace.behavior-alert.v1"))));
            assertTrue(delivered.await(3, TimeUnit.SECONDS));
        } finally {
            server.stop(0);
        }
        assertEquals("BEHAVIOR_HIGH_RISK", received.get().path("type").asText());
        assertEquals("SERVER_CONFIRMED", received.get().path("origin").asText());
        assertFalse(received.get().path("corroborated").asBoolean());
    }

    @Test
    void rejectsPlainHttpOutsideLoopback() throws Exception {
        KeyPair identity = Ed25519Keys.generate(new java.security.SecureRandom());
        assertThrows(IllegalArgumentException.class, () -> new CloudClientConfiguration(
                URI.create("http://example.com"), "paper-test", identity.getPrivate(), 8, Duration.ofSeconds(2)));
    }

    private static JsonNode read(HttpExchange exchange) throws IOException {
        return MAPPER.readTree(exchange.getRequestBody());
    }

    private static boolean verify(KeyPair identity, byte[] payload, String encodedSignature) throws IOException {
        try {
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(identity.getPublic());
            verifier.update(payload);
            return verifier.verify(Base64.getUrlDecoder().decode(encodedSignature));
        } catch (java.security.GeneralSecurityException | IllegalArgumentException exception) {
            throw new IOException("failed to verify client proof", exception);
        }
    }

    private static void write(HttpExchange exchange, int status, Map<String, ?> body) throws IOException {
        byte[] encoded = MAPPER.writeValueAsBytes(body);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, encoded.length);
        exchange.getResponseBody().write(encoded);
        exchange.close();
    }
}
