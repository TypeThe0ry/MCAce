package com.ellan.mcace.core.federation;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

final class FederationConfigurationTest {
    @TempDir Path temporaryDirectory;

    @Test
    void createsACompleteDisabledDefaultWithoutOpeningAnyTransport() throws Exception {
        Path path = temporaryDirectory.resolve(FederationConfiguration.FILE_NAME);
        FederationConfiguration configuration = FederationConfiguration.loadOrCreate(path);

        assertFalse(configuration.enabled());
        assertEquals("mcace-local", configuration.localNetworkId());
        assertEquals(Duration.ofMinutes(2), configuration.assertionLifetime());
        assertTrue(configuration.peers().isEmpty());
        assertTrue(Files.readString(path).contains("enabled=false"));
    }

    @Test
    void loadsAnExplicitPeerOnlyWhenThePublicKeyAndPinAgree() throws Exception {
        KeyPair peer = Ed25519Keys.generate(new SecureRandom());
        FederationConfiguration configuration = FederationConfiguration.parse(configuration(peer, true));

        assertTrue(configuration.enabled());
        assertEquals(1, configuration.peers().size());
        FederationPeerPin pin = configuration.requirePeer(
                "target-network", FederationPeerCapability.ISSUE_TO);
        assertArrayEquals(sha256(peer.getPublic().getEncoded()), pin.keyIdSha256());
        assertEquals(Set.of(FederationPeerCapability.ISSUE_TO), pin.capabilities());
        assertThrows(IllegalArgumentException.class, () -> configuration.requirePeer(
                "target-network", FederationPeerCapability.ACCEPT_FROM));
    }

    @Test
    void rejectsPartialDuplicateUnknownAndMismatchedPinDocumentsAtomically() throws Exception {
        KeyPair peer = Ed25519Keys.generate(new SecureRandom());
        String valid = configuration(peer, true);

        assertThrows(IOException.class, () -> FederationConfiguration.parse(
                valid.replace("peer.target-network.key-id-sha256=" + hex(sha256(peer.getPublic().getEncoded())),
                        "peer.target-network.key-id-sha256=" + "00".repeat(32))));
        assertThrows(IOException.class, () -> FederationConfiguration.parse(
                valid.replaceFirst("peer.target-network.key-id-sha256=.*\\R", "")));
        assertThrows(IOException.class, () -> FederationConfiguration.parse(valid + "unknown.setting=true\n"));
        assertThrows(IOException.class, () -> FederationConfiguration.parse(valid + "enabled=false\n"));
        assertThrows(IOException.class, () -> FederationConfiguration.parse(
                valid.replace("assertion.ttl.seconds=120", "assertion.ttl.seconds=301")));
        assertThrows(IOException.class, () -> FederationConfiguration.parse(
                valid.replace("peer.target-network.capabilities=ISSUE_TO",
                        "peer.target-network.capabilities=BOTH")));
    }

    @Test
    void failedReloadLeavesAnOperatorOwnedFileUntouched() throws Exception {
        Path path = temporaryDirectory.resolve(FederationConfiguration.FILE_NAME);
        String invalid = "schema.version=1\nenabled=true\nlocal.network-id=local\n"
                + "assertion.ttl.seconds=120\npeer.ids=missing\n";
        Files.writeString(path, invalid, StandardCharsets.UTF_8);

        assertThrows(IOException.class, () -> FederationConfiguration.loadOrCreate(path));
        assertEquals(invalid, Files.readString(path, StandardCharsets.UTF_8));
    }

    @Test
    void rejectsDifferentPeerIdsThatReuseOneIdentityKey() throws Exception {
        KeyPair shared = Ed25519Keys.generate(new SecureRandom());
        String encoded = Base64.getEncoder().encodeToString(shared.getPublic().getEncoded());
        String pin = hex(sha256(shared.getPublic().getEncoded()));
        String duplicateIdentity = """
                schema.version=1
                enabled=true
                local.network-id=target-network
                assertion.ttl.seconds=120
                peer.ids=source-a,source-b
                peer.source-a.public-key-x509-base64=%s
                peer.source-a.key-id-sha256=%s
                peer.source-a.capabilities=ACCEPT_FROM
                peer.source-b.public-key-x509-base64=%s
                peer.source-b.key-id-sha256=%s
                peer.source-b.capabilities=ACCEPT_FROM
                """.formatted(encoded, pin, encoded, pin);

        assertThrows(IOException.class, () -> FederationConfiguration.parse(duplicateIdentity));
    }

    private static String configuration(KeyPair peer, boolean enabled) throws Exception {
        return """
                schema.version=1
                enabled=%s
                local.network-id=source-network
                assertion.ttl.seconds=120
                peer.ids=target-network
                peer.target-network.public-key-x509-base64=%s
                peer.target-network.key-id-sha256=%s
                peer.target-network.capabilities=ISSUE_TO
                """.formatted(enabled,
                Base64.getEncoder().encodeToString(peer.getPublic().getEncoded()),
                hex(sha256(peer.getPublic().getEncoded())));
    }

    private static byte[] sha256(byte[] value) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(value);
    }

    private static String hex(byte[] value) {
        return HexFormat.of().formatHex(value);
    }
}
