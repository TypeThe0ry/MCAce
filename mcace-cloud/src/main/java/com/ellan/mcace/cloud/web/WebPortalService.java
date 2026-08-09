package com.ellan.mcace.cloud.web;

import com.ellan.mcace.core.persistence.SecurityPersistenceException;
import com.ellan.mcace.core.persistence.StoredWebSession;
import com.ellan.mcace.core.persistence.WebPortalStore;
import com.ellan.mcace.core.persistence.WebPrincipalType;
import com.ellan.mcace.core.persistence.WebRole;
import com.ellan.mcace.core.persistence.WebSessionHandoff;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

public final class WebPortalService {
    private static final byte[] HASH_DOMAIN = "mcace-web-secret-v1\0".getBytes(StandardCharsets.UTF_8);
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();
    private static final Duration HANDOFF_LIFETIME = Duration.ofMinutes(2);
    private static final Duration SESSION_LIFETIME = Duration.ofHours(8);

    private final WebPortalStore store;
    private final Clock clock;
    private final SecureRandom random;

    public WebPortalService(WebPortalStore store, Clock clock, SecureRandom random) {
        this.store = Objects.requireNonNull(store, "store");
        this.clock = Objects.requireNonNull(clock, "clock");
        this.random = Objects.requireNonNull(random, "random");
    }

    public IssuedWebHandoff issueOperator(
            String subjectId, Set<WebRole> roles, String redirectPath, String createdBy)
            throws SecurityPersistenceException {
        return issue(WebPrincipalType.OPERATOR, subjectId, roles, redirectPath, createdBy);
    }

    public IssuedWebHandoff issuePlayer(
            UUID playerId, String redirectPath, String createdBy) throws SecurityPersistenceException {
        Objects.requireNonNull(playerId, "playerId");
        return issue(WebPrincipalType.PLAYER, playerId.toString(), Set.of(WebRole.PLAYER),
                redirectPath, createdBy);
    }

    public EstablishedWebSession exchange(String code)
            throws SecurityPersistenceException, WebPortalException {
        TokenParts parts = parse(code, WebPortalException.Kind.INVALID_HANDOFF);
        Optional<WebSessionHandoff> consumed = store.consumeWebHandoff(parts.id());
        if (consumed.isEmpty()) {
            throw new WebPortalException(
                    WebPortalException.Kind.INVALID_HANDOFF, "web handoff is invalid or already used");
        }
        WebSessionHandoff handoff = consumed.orElseThrow();
        Instant now = clock.instant();
        if (!MessageDigest.isEqual(handoff.secretSha256(), hash(parts.secret()))
                || !handoff.expiresAt().isAfter(now)) {
            throw new WebPortalException(
                    WebPortalException.Kind.INVALID_HANDOFF, "web handoff is invalid or already used");
        }

        byte[] secret = randomBytes();
        StoredWebSession session = new StoredWebSession(
                UUID.randomUUID(), hash(secret), handoff.principalType(), handoff.subjectId(), handoff.roles(),
                handoff.createdBy(), now, now.plus(SESSION_LIFETIME));
        store.createWebSession(session);
        return new EstablishedWebSession(
                session, encode(session.sessionId(), secret), ENCODER.encodeToString(randomBytes()),
                handoff.redirectPath());
    }

    public StoredWebSession authenticate(String cookieToken)
            throws SecurityPersistenceException, WebPortalException {
        TokenParts parts = parse(cookieToken, WebPortalException.Kind.INVALID_SESSION);
        StoredWebSession session = store.findActiveWebSession(hash(parts.secret()), clock.instant())
                .filter(value -> value.sessionId().equals(parts.id()))
                .orElseThrow(() -> new WebPortalException(
                        WebPortalException.Kind.INVALID_SESSION, "web session is invalid or expired"));
        return session;
    }

    public void logout(String cookieToken) throws SecurityPersistenceException, WebPortalException {
        TokenParts parts = parse(cookieToken, WebPortalException.Kind.INVALID_SESSION);
        byte[] hash = hash(parts.secret());
        StoredWebSession session = store.findActiveWebSession(hash, clock.instant())
                .filter(value -> value.sessionId().equals(parts.id()))
                .orElseThrow(() -> new WebPortalException(
                        WebPortalException.Kind.INVALID_SESSION, "web session is invalid or expired"));
        store.deleteWebSession(session.sessionId(), hash);
    }

    public static void requireCsrf(String csrfCookie, String csrfHeader) throws WebPortalException {
        if (csrfCookie == null || csrfHeader == null
                || csrfCookie.length() < 32 || csrfCookie.length() > 128
                || !MessageDigest.isEqual(
                        csrfCookie.getBytes(StandardCharsets.US_ASCII),
                        csrfHeader.getBytes(StandardCharsets.US_ASCII))) {
            throw new WebPortalException(WebPortalException.Kind.CSRF_REJECTED, "CSRF validation failed");
        }
    }

    private IssuedWebHandoff issue(
            WebPrincipalType principalType,
            String subjectId,
            Set<WebRole> roles,
            String redirectPath,
            String createdBy) throws SecurityPersistenceException {
        byte[] secret = randomBytes();
        Instant now = clock.instant();
        WebSessionHandoff handoff = new WebSessionHandoff(
                UUID.randomUUID(), hash(secret), principalType, subjectId, roles, redirectPath,
                createdBy, now, now.plus(HANDOFF_LIFETIME));
        store.createWebHandoff(handoff);
        return new IssuedWebHandoff(
                encode(handoff.handoffId(), secret), handoff.redirectPath(), handoff.expiresAt());
    }

    private byte[] randomBytes() {
        byte[] value = new byte[32];
        random.nextBytes(value);
        return value;
    }

    private static String encode(UUID id, byte[] secret) {
        return id + "." + ENCODER.encodeToString(secret);
    }

    private static TokenParts parse(String value, WebPortalException.Kind kind)
            throws WebPortalException {
        try {
            if (value == null || value.length() > 160) throw new IllegalArgumentException("token length");
            int separator = value.indexOf('.');
            if (separator <= 0 || separator != value.lastIndexOf('.')) {
                throw new IllegalArgumentException("token format");
            }
            UUID id = UUID.fromString(value.substring(0, separator));
            byte[] secret = DECODER.decode(value.substring(separator + 1));
            if (secret.length != 32) throw new IllegalArgumentException("secret length");
            return new TokenParts(id, secret);
        } catch (IllegalArgumentException exception) {
            throw new WebPortalException(kind,
                    kind == WebPortalException.Kind.INVALID_HANDOFF
                            ? "web handoff is invalid or already used"
                            : "web session is invalid or expired");
        }
    }

    private static byte[] hash(byte[] secret) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(HASH_DOMAIN);
            return digest.digest(secret);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    private record TokenParts(UUID id, byte[] secret) {
        private TokenParts {
            secret = secret.clone();
        }
    }
}
