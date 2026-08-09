package com.ellan.mcace.cloud.anchor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.ellan.mcace.core.persistence.StoredAuditAnchor;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

final class HttpsAuditAnchorPublisherTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Instant NOW = Instant.parse("2026-08-08T12:30:00Z");

    @Test
    void publishesBoundedSignedHeadWithIdempotencyAndReceipt() throws Exception {
        AtomicReference<JsonNode> received = new AtomicReference<>();
        AtomicReference<String> authorization = new AtomicReference<>();
        AtomicReference<String> idempotency = new AtomicReference<>();
        byte[] receiptBody = "{\"stored\":true}".getBytes(StandardCharsets.UTF_8);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/anchors", exchange -> {
            authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            idempotency.set(exchange.getRequestHeaders().getFirst("Idempotency-Key"));
            received.set(JSON.readTree(exchange.getRequestBody()));
            exchange.getResponseHeaders().set("X-MCAce-Anchor-Receipt", "external-ledger-42");
            exchange.sendResponseHeaders(201, receiptBody.length);
            exchange.getResponseBody().write(receiptBody);
            exchange.close();
        });
        server.start();
        StoredAuditAnchor anchor = anchor();
        URI endpoint = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/anchors");
        try {
            var publisher = new HttpsAuditAnchorPublisher(
                    endpoint, "test-bearer", Duration.ofSeconds(2),
                    Clock.fixed(NOW, ZoneOffset.UTC));
            var publication = publisher.publish(anchor);
            assertEquals(endpoint, publication.destination());
            assertEquals("external-ledger-42", publication.receiptReference());
            assertArrayEquals(MessageDigest.getInstance("SHA-256").digest(receiptBody),
                    publication.receiptSha256());
        } finally {
            server.stop(0);
        }
        assertEquals("Bearer test-bearer", authorization.get());
        assertEquals(anchor.anchorId().toString(), idempotency.get());
        assertEquals("mcace.audit-anchor.v1", received.get().path("schema").asText());
        assertEquals(1, received.get().path("sequence").asLong());
        assertEquals(86, received.get().path("server_signature").asText().length());
    }

    @Test
    void rejectsRemotePlaintextEndpoint() {
        assertThrows(IllegalArgumentException.class, () -> new HttpsAuditAnchorPublisher(
                URI.create("http://example.com/anchors"), "", Duration.ofSeconds(2), Clock.systemUTC()));
    }

    private static StoredAuditAnchor anchor() {
        byte[] one = new byte[32];
        byte[] two = new byte[32];
        byte[] three = new byte[32];
        byte[] four = new byte[32];
        java.util.Arrays.fill(one, (byte) 1);
        java.util.Arrays.fill(two, (byte) 2);
        java.util.Arrays.fill(three, (byte) 3);
        java.util.Arrays.fill(four, (byte) 4);
        return new StoredAuditAnchor(
                UUID.fromString("11111111-1111-1111-1111-111111111111"), 1, NOW,
                5, one, 2, 3, two, 7, three, new byte[32], four, new byte[64], "test-key");
    }
}
