package com.ellan.mcace.cloud.auth;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record IssuedChallenge(UUID challengeId, byte[] signingPayload, Instant expiresAt) {
    public IssuedChallenge {
        Objects.requireNonNull(challengeId, "challengeId");
        Objects.requireNonNull(signingPayload, "signingPayload");
        Objects.requireNonNull(expiresAt, "expiresAt");
        signingPayload = signingPayload.clone();
    }

    @Override public byte[] signingPayload() { return signingPayload.clone(); }
}
