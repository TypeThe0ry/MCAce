package com.ellan.mcace.core.authority;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

final class BackendAuthorityRegistryTest {
    @Test
    void emptyRegistryIsTheOnlyDefaultAndContainsNoImplicitPins() {
        BackendAuthorityRegistry disabled = BackendAuthorityRegistry.disabled();

        assertFalse(disabled.enabled());
        assertEquals(0, disabled.size());
        assertTrue(disabled.pinForRegisteredBackend(AuthorityTestFixtures.REGISTERED_BACKEND).isEmpty());
        assertTrue(disabled.pinForRegisteredBackend("unknown").isEmpty());
    }

    @Test
    void registryRequiresAnExactBackendKeyAndDefensivelyCopiesItsInputs() throws Exception {
        KeyPair keys = AuthorityTestFixtures.keyPair();
        HashMap<String, BackendAuthorityProfile> profiles = new HashMap<>(
                Map.of(AuthorityTestFixtures.PROFILE, AuthorityTestFixtures.AUTHORITY_PROFILE));
        BackendAuthorityPin pin = new BackendAuthorityPin(
                AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.BACKEND_INSTANCE,
                AuthorityTestFixtures.fingerprint(keys),
                keys.getPublic(),
                profiles);
        HashMap<String, BackendAuthorityPin> source = new HashMap<>();
        source.put(AuthorityTestFixtures.REGISTERED_BACKEND, pin);
        BackendAuthorityRegistry registry = new BackendAuthorityRegistry(source);

        profiles.clear();
        source.clear();

        assertTrue(registry.enabled());
        assertEquals(1, registry.size());
        BackendAuthorityPin retained = registry.pinForRegisteredBackend(
                AuthorityTestFixtures.REGISTERED_BACKEND).orElseThrow();
        assertEquals(Set.of(AuthorityTestFixtures.PROFILE), retained.allowedProfileSha256());
        assertEquals(AuthorityTestFixtures.AUTHORITY_PROFILE,
                retained.authorityProfile(AuthorityTestFixtures.PROFILE).orElseThrow());
        assertThrows(UnsupportedOperationException.class,
                () -> retained.allowedProfileSha256().add(AuthorityTestFixtures.OTHER_PROFILE));
        assertThrows(UnsupportedOperationException.class,
                () -> retained.authorityProfiles().put(
                        AuthorityTestFixtures.OTHER_PROFILE, AuthorityTestFixtures.AUTHORITY_PROFILE));
        assertTrue(registry.pinForRegisteredBackend("SURVIVAL").isEmpty());
        assertTrue(registry.pinForRegisteredBackend("survival ").isEmpty());
    }

    @Test
    void pinRejectsAKeyIdThatDoesNotMatchTheEd25519PublicKey() throws Exception {
        KeyPair keys = AuthorityTestFixtures.keyPair();

        assertThrows(IllegalArgumentException.class, () -> new BackendAuthorityPin(
                AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.BACKEND_INSTANCE,
                "00".repeat(32),
                keys.getPublic(),
                Map.of(AuthorityTestFixtures.PROFILE, AuthorityTestFixtures.AUTHORITY_PROFILE)));
    }

    @Test
    void pinRejectsWrongKeyTypeInvalidProfilesAndUnsafeQuorum() throws Exception {
        KeyPair rsa = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        String rsaFingerprint = HexFormat.of().formatHex(
                MessageDigest.getInstance("SHA-256").digest(rsa.getPublic().getEncoded()));

        assertThrows(IllegalArgumentException.class, () -> new BackendAuthorityPin(
                AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.BACKEND_INSTANCE,
                rsaFingerprint,
                rsa.getPublic(),
                Map.of(AuthorityTestFixtures.PROFILE, AuthorityTestFixtures.AUTHORITY_PROFILE)));

        KeyPair keys = AuthorityTestFixtures.keyPair();
        String keyId = AuthorityTestFixtures.fingerprint(keys);
        assertThrows(IllegalArgumentException.class, () -> new BackendAuthorityPin(
                AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.BACKEND_INSTANCE,
                keyId,
                keys.getPublic(),
                Map.of()));
        assertThrows(IllegalArgumentException.class, () -> new BackendAuthorityPin(
                AuthorityTestFixtures.REGISTERED_BACKEND,
                AuthorityTestFixtures.BACKEND_INSTANCE,
                keyId,
                keys.getPublic(),
                Map.of("AB".repeat(32), AuthorityTestFixtures.AUTHORITY_PROFILE)));
        assertThrows(IllegalArgumentException.class, () -> new BackendAuthorityProfile(
                List.of(
                        new BackendAuthorityProfile.ProviderContract(
                                "grim-domain", "grim", "1.0.0", "movement-stable", 2),
                        new BackendAuthorityProfile.ProviderContract(
                                "vulcan-domain", "vulcan", "1.0.0", "movement-stable", 2)),
                1, java.time.Duration.ofSeconds(10), java.time.Duration.ZERO));
        assertThrows(IllegalArgumentException.class, () -> new BackendAuthorityProfile(
                List.of(
                        new BackendAuthorityProfile.ProviderContract(
                                "grim-domain", "grim", "1.0.0", "movement-stable", 2),
                        new BackendAuthorityProfile.ProviderContract(
                                "vulcan-domain", "vulcan", "1.0.0", "movement-stable", 2)),
                3, java.time.Duration.ofSeconds(10), java.time.Duration.ZERO));
        BackendAuthorityProfile changedThreshold = new BackendAuthorityProfile(
                List.of(
                        new BackendAuthorityProfile.ProviderContract(
                                "grim-domain", "grim", "1.0.0", "movement-stable", 3),
                        new BackendAuthorityProfile.ProviderContract(
                                "vulcan-domain", "vulcan", "1.0.0", "movement-stable", 2)),
                2, java.time.Duration.ofSeconds(15), java.time.Duration.ofSeconds(30));
        assertNotEquals(AuthorityTestFixtures.PROFILE, changedThreshold.sha256());
        assertThrows(IllegalArgumentException.class, () -> new BackendAuthorityPin(
                "unsafe\nbackend",
                AuthorityTestFixtures.BACKEND_INSTANCE,
                keyId,
                keys.getPublic(),
                Map.of(AuthorityTestFixtures.PROFILE, AuthorityTestFixtures.AUTHORITY_PROFILE)));
    }

    @Test
    void registryRejectsMapKeysThatDoNotExactlyMatchTheirPin() throws Exception {
        BackendAuthorityPin pin = AuthorityTestFixtures.pin(AuthorityTestFixtures.keyPair());

        assertThrows(IllegalArgumentException.class,
                () -> new BackendAuthorityRegistry(Map.of("other-backend", pin)));
    }
}
