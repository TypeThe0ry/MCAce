package com.ellan.mcace.cloud.auth;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface AuthenticationChallengeStore {
    void create(
            StoredAuthenticationChallenge challenge,
            Instant now,
            int maximumOutstanding,
            int maximumPerServer) throws AuthenticationException;

    Optional<StoredAuthenticationChallenge> consume(UUID challengeId) throws AuthenticationException;
}
