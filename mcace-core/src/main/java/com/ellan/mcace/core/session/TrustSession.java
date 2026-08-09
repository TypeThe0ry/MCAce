package com.ellan.mcace.core.session;

import com.ellan.mcace.protocol.generated.TrustLevel;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

public final class TrustSession {
    private final String id;
    private final UUID playerId;
    private final Instant createdAt;
    private SessionStage stage;
    private PublicKey clientPublicKey;
    private TrustLevel trustLevel;

    public TrustSession(String id, UUID playerId, Instant createdAt) {
        this.id = requireText(id, "id");
        this.playerId = Objects.requireNonNull(playerId, "playerId");
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt");
        this.stage = SessionStage.CONNECTING;
        this.trustLevel = TrustLevel.UNKNOWN;
    }

    public synchronized void challengeSent() {
        transition(SessionStage.CONNECTING, SessionStage.CHALLENGE_SENT);
    }

    public synchronized void identifyClient(PublicKey publicKey) {
        transition(SessionStage.CHALLENGE_SENT, SessionStage.CLIENT_IDENTIFIED);
        clientPublicKey = Objects.requireNonNull(publicKey, "publicKey");
    }

    public synchronized void authenticate(TrustLevel level) {
        Objects.requireNonNull(level, "level");
        if (level == TrustLevel.UNKNOWN || level == TrustLevel.UNRECOGNIZED) {
            throw new IllegalArgumentException("authenticated session requires a known trust level");
        }
        transition(SessionStage.CLIENT_IDENTIFIED, SessionStage.AUTHENTICATED);
        trustLevel = level;
    }

    public synchronized void reject() {
        if (terminal()) {
            return;
        }
        stage = SessionStage.REJECTED;
    }

    public synchronized void expire() {
        if (terminal()) {
            return;
        }
        stage = SessionStage.EXPIRED;
    }

    public String id() {
        return id;
    }

    public UUID playerId() {
        return playerId;
    }

    public Instant createdAt() {
        return createdAt;
    }

    public synchronized SessionStage stage() {
        return stage;
    }

    public synchronized Optional<PublicKey> clientPublicKey() {
        return Optional.ofNullable(clientPublicKey);
    }

    public synchronized TrustLevel trustLevel() {
        return trustLevel;
    }

    private boolean terminal() {
        return stage == SessionStage.EXPIRED || stage == SessionStage.REJECTED;
    }

    private void transition(SessionStage expected, SessionStage next) {
        if (stage != expected) {
            throw new IllegalStateException("invalid session transition from " + stage + " to " + next);
        }
        stage = next;
    }

    private static String requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return value;
    }
}
