package com.ellan.mcace.cloud.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;

final class CloudAuthenticationServiceTest {
    private static final Instant NOW = Instant.parse("2026-08-08T10:00:00Z");

    @Test
    void exchangesAOneTimeServerProofForAScopedSignedToken() throws Exception {
        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        KeyPair cloud = Ed25519Keys.generate(new SecureRandom());
        MutableClock clock = new MutableClock(NOW);
        ServerIdentity identity = new ServerIdentity(
                "velocity-a", server.getPublic(), EnumSet.of(ApiScope.RISK_WRITE, ApiScope.EVIDENCE_WRITE));
        AccessTokenCodec tokens = new AccessTokenCodec(
                cloud.getPrivate(), cloud.getPublic(), clock, Duration.ofMinutes(5));
        CloudAuthenticationService service = new CloudAuthenticationService(
                FileServerIdentityRegistry.of(identity), tokens, clock, new SecureRandom(), Duration.ofSeconds(30));

        IssuedChallenge challenge = service.issue(identity.serverId());
        String proof = sign(server, challenge.signingPayload());
        String token = service.exchange(challenge.challengeId(), identity.serverId(), proof);
        AuthenticatedServer authenticated = service.authenticate(token);

        assertEquals(identity.serverId(), authenticated.serverId());
        assertTrue(authenticated.permits(ApiScope.RISK_WRITE));
        assertThrows(AuthenticationException.class,
                () -> service.exchange(challenge.challengeId(), identity.serverId(), proof));
        assertThrows(AuthenticationException.class, () -> service.authenticate(token + "x"));

        clock.advance(Duration.ofMinutes(6));
        assertThrows(AuthenticationException.class, () -> service.authenticate(token));
    }

    @Test
    void burnsAChallengeAfterAForgedProof() throws Exception {
        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        KeyPair attacker = Ed25519Keys.generate(new SecureRandom());
        KeyPair cloud = Ed25519Keys.generate(new SecureRandom());
        ServerIdentity identity = new ServerIdentity(
                "velocity-a", server.getPublic(), EnumSet.of(ApiScope.RISK_WRITE));
        AccessTokenCodec tokens = new AccessTokenCodec(
                cloud.getPrivate(), cloud.getPublic(), Clock.fixed(NOW, ZoneOffset.UTC), Duration.ofMinutes(5));
        CloudAuthenticationService service = new CloudAuthenticationService(
                FileServerIdentityRegistry.of(identity), tokens, Clock.fixed(NOW, ZoneOffset.UTC),
                new SecureRandom(), Duration.ofSeconds(30));
        IssuedChallenge challenge = service.issue(identity.serverId());

        assertThrows(AuthenticationException.class, () -> service.exchange(
                challenge.challengeId(), identity.serverId(), sign(attacker, challenge.signingPayload())));
        assertThrows(AuthenticationException.class, () -> service.exchange(
                challenge.challengeId(), identity.serverId(), sign(server, challenge.signingPayload())));
    }

    @Test
    void exchangesAcrossInstancesAndAtomicallyRejectsConcurrentReplay() throws Exception {
        KeyPair server = Ed25519Keys.generate(new SecureRandom());
        KeyPair cloud = Ed25519Keys.generate(new SecureRandom());
        ServerIdentity identity = new ServerIdentity(
                "paper-shared", server.getPublic(), EnumSet.of(ApiScope.RISK_WRITE));
        InMemoryAuthenticationChallengeStore sharedStore = new InMemoryAuthenticationChallengeStore();
        Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
        AccessTokenCodec codec = new AccessTokenCodec(
                cloud.getPrivate(), cloud.getPublic(), clock, Duration.ofMinutes(5));
        CloudAuthenticationService first = new CloudAuthenticationService(
                FileServerIdentityRegistry.of(identity), codec, clock, new SecureRandom(),
                Duration.ofSeconds(30), sharedStore);
        CloudAuthenticationService second = new CloudAuthenticationService(
                FileServerIdentityRegistry.of(identity), codec, clock, new SecureRandom(),
                Duration.ofSeconds(30), sharedStore);
        IssuedChallenge challenge = first.issue(identity.serverId());
        String proof = sign(server, challenge.signingPayload());
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            List<Future<Boolean>> attempts = List.of(
                    executor.submit(() -> exchangeAfterGate(first, challenge, identity.serverId(), proof, ready, start)),
                    executor.submit(() -> exchangeAfterGate(second, challenge, identity.serverId(), proof, ready, start)));
            assertTrue(ready.await(2, java.util.concurrent.TimeUnit.SECONDS));
            start.countDown();
            assertEquals(1, attempts.stream().filter(CloudAuthenticationServiceTest::successful).count());
        }
    }

    private static boolean exchangeAfterGate(
            CloudAuthenticationService service,
            IssuedChallenge challenge,
            String serverId,
            String proof,
            CountDownLatch ready,
            CountDownLatch start) throws InterruptedException {
        ready.countDown();
        start.await();
        try {
            service.exchange(challenge.challengeId(), serverId, proof);
            return true;
        } catch (AuthenticationException exception) {
            return false;
        }
    }

    private static boolean successful(Future<Boolean> attempt) {
        try {
            return attempt.get();
        } catch (Exception exception) {
            throw new AssertionError("concurrent authentication attempt failed unexpectedly", exception);
        }
    }

    private static String sign(KeyPair keyPair, byte[] payload) throws Exception {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(keyPair.getPrivate());
        signature.update(payload);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign());
    }

    private static final class MutableClock extends Clock {
        private Instant current;

        private MutableClock(Instant current) {
            this.current = current;
        }

        private void advance(Duration duration) {
            current = current.plus(duration);
        }

        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return current; }
    }
}
