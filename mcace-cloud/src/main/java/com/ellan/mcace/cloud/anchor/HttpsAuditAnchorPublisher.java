package com.ellan.mcace.cloud.anchor;

import com.ellan.mcace.core.persistence.AuditAnchorPublication;
import com.ellan.mcace.core.persistence.StoredAuditAnchor;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public final class HttpsAuditAnchorPublisher implements AuditAnchorPublisher {
    private static final int MAX_RESPONSE_BYTES = 16_384;

    private final URI endpoint;
    private final String bearerToken;
    private final Duration requestTimeout;
    private final HttpClient client;
    private final ObjectMapper mapper;
    private final Clock clock;

    public HttpsAuditAnchorPublisher(
            URI endpoint, String bearerToken, Duration requestTimeout, Clock clock) {
        this(endpoint, bearerToken, requestTimeout, clock,
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build(), new ObjectMapper());
    }

    HttpsAuditAnchorPublisher(
            URI endpoint,
            String bearerToken,
            Duration requestTimeout,
            Clock clock,
            HttpClient client,
            ObjectMapper mapper) {
        this.endpoint = validateEndpoint(endpoint);
        this.bearerToken = validateBearer(bearerToken);
        this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout");
        if (requestTimeout.isZero() || requestTimeout.isNegative()
                || requestTimeout.compareTo(Duration.ofSeconds(30)) > 0) {
            throw new IllegalArgumentException("requestTimeout must be between 1 ms and 30 seconds");
        }
        this.clock = Objects.requireNonNull(clock, "clock");
        this.client = Objects.requireNonNull(client, "client");
        this.mapper = Objects.requireNonNull(mapper, "mapper");
    }

    @Override
    public AuditAnchorPublication publish(StoredAuditAnchor anchor)
            throws AuditAnchorPublicationException {
        Objects.requireNonNull(anchor, "anchor");
        try {
            byte[] body = mapper.writeValueAsBytes(payload(anchor));
            HttpRequest.Builder request = HttpRequest.newBuilder(endpoint)
                    .timeout(requestTimeout)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .header("Idempotency-Key", anchor.anchorId().toString())
                    .header("User-Agent", "MCAce-Cloud-AuditAnchor/1")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body));
            if (!bearerToken.isEmpty()) {
                request.header("Authorization", "Bearer " + bearerToken);
            }
            HttpResponse<InputStream> response = client.send(
                    request.build(), HttpResponse.BodyHandlers.ofInputStream());
            byte[] receiptBody;
            try (InputStream input = response.body()) {
                receiptBody = input.readNBytes(MAX_RESPONSE_BYTES + 1);
            }
            if (receiptBody.length > MAX_RESPONSE_BYTES) {
                throw new AuditAnchorPublicationException("audit anchor receipt exceeds size limit");
            }
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new AuditAnchorPublicationException(
                        "audit anchor endpoint returned HTTP " + response.statusCode());
            }
            String receipt = response.headers().firstValue("X-MCAce-Anchor-Receipt").orElse("").strip();
            if (receipt.isEmpty() || receipt.length() > 256 || containsControl(receipt)) {
                throw new AuditAnchorPublicationException("audit anchor endpoint omitted a valid receipt");
            }
            return new AuditAnchorPublication(
                    endpoint, clock.instant(), receipt,
                    MessageDigest.getInstance("SHA-256").digest(receiptBody));
        } catch (IOException | InterruptedException | GeneralSecurityException exception) {
            if (exception instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new AuditAnchorPublicationException("audit anchor publication failed", exception);
        }
    }

    private static Map<String, Object> payload(StoredAuditAnchor anchor) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("schema", "mcace.audit-anchor.v1");
        body.put("anchor_id", anchor.anchorId().toString());
        body.put("sequence", anchor.sequence());
        body.put("created_at", anchor.createdAt().toString());
        body.put("evidence_sequence", anchor.evidenceSequence());
        body.put("evidence_chain_sha256", hex(anchor.evidenceChainSha256()));
        body.put("revocation_count", anchor.revocationCount());
        body.put("revocation_max_sequence", anchor.revocationMaxSequence());
        body.put("revocation_feed_sha256", hex(anchor.revocationFeedSha256()));
        body.put("operator_audit_count", anchor.operatorAuditCount());
        body.put("operator_audit_sha256", hex(anchor.operatorAuditSha256()));
        body.put("previous_anchor_sha256", hex(anchor.previousAnchorSha256()));
        body.put("anchor_sha256", hex(anchor.anchorSha256()));
        body.put("signature_algorithm", "Ed25519");
        body.put("server_signature", Base64.getUrlEncoder().withoutPadding()
                .encodeToString(anchor.serverSignature()));
        body.put("signer_key_id", anchor.signerKeyId());
        return body;
    }

    private static URI validateEndpoint(URI endpoint) {
        Objects.requireNonNull(endpoint, "endpoint");
        if (!endpoint.isAbsolute() || endpoint.getHost() == null || endpoint.getUserInfo() != null
                || endpoint.getQuery() != null || endpoint.getFragment() != null) {
            throw new IllegalArgumentException("audit anchor endpoint is invalid");
        }
        if ("https".equalsIgnoreCase(endpoint.getScheme())) {
            return endpoint;
        }
        if (!"http".equalsIgnoreCase(endpoint.getScheme())) {
            throw new IllegalArgumentException("audit anchor endpoint must use HTTPS");
        }
        try {
            if (!InetAddress.getByName(endpoint.getHost()).isLoopbackAddress()) {
                throw new IllegalArgumentException("plain HTTP audit anchoring is loopback-only");
            }
        } catch (IOException exception) {
            throw new IllegalArgumentException("audit anchor endpoint host cannot be resolved", exception);
        }
        return endpoint;
    }

    private static String validateBearer(String token) {
        if (token == null || token.isBlank()) {
            return "";
        }
        if (token.length() > 4096 || containsControl(token)) {
            throw new IllegalArgumentException("audit anchor bearer credential is invalid");
        }
        return token;
    }

    private static boolean containsControl(String value) {
        return value.chars().anyMatch(character -> character < 0x20 || character == 0x7f);
    }

    private static String hex(byte[] value) {
        return HexFormat.of().formatHex(value);
    }
}
