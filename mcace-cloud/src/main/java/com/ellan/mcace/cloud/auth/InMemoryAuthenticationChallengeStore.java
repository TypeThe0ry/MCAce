package com.ellan.mcace.cloud.auth;

import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

public final class InMemoryAuthenticationChallengeStore implements AuthenticationChallengeStore {
    private final Map<UUID, StoredAuthenticationChallenge> challenges = new LinkedHashMap<>();

    @Override
    public synchronized void create(
            StoredAuthenticationChallenge challenge,
            Instant now,
            int maximumOutstanding,
            int maximumPerServer) throws AuthenticationException {
        Objects.requireNonNull(challenge, "challenge");
        Objects.requireNonNull(now, "now");
        purgeExpired(now);
        long serverCount = challenges.values().stream()
                .filter(value -> value.serverId().equals(challenge.serverId()))
                .count();
        if (challenges.size() >= maximumOutstanding || serverCount >= maximumPerServer) {
            throw new AuthenticationException("too many outstanding authentication challenges");
        }
        if (challenges.putIfAbsent(challenge.challengeId(), challenge) != null) {
            throw new AuthenticationException("duplicate authentication challenge");
        }
    }

    @Override
    public synchronized Optional<StoredAuthenticationChallenge> consume(UUID challengeId) {
        return Optional.ofNullable(challenges.remove(Objects.requireNonNull(challengeId, "challengeId")));
    }

    private void purgeExpired(Instant now) {
        Iterator<StoredAuthenticationChallenge> iterator = challenges.values().iterator();
        while (iterator.hasNext()) {
            if (!iterator.next().expiresAt().isAfter(now)) {
                iterator.remove();
            }
        }
    }
}
