package com.ellan.mcace.core.federation;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.Ed25519Keys;
import com.ellan.mcace.protocol.crypto.EnvelopeException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;

/** Operator-pinned Ed25519 identity for one explicitly trusted federation peer. */
public record FederationPeerPin(
        String networkId,
        PublicKey publicKey,
        byte[] keyIdSha256,
        Set<FederationPeerCapability> capabilities) {
    public FederationPeerPin {
        requireNetworkId(networkId);
        Objects.requireNonNull(publicKey, "publicKey");
        byte[] encoded = Objects.requireNonNull(publicKey.getEncoded(), "encoded publicKey").clone();
        if (encoded.length == 0 || encoded.length > 128) {
            throw new IllegalArgumentException("invalid federation peer public key size");
        }
        try {
            Ed25519Keys.decodePublic(encoded);
        } catch (EnvelopeException exception) {
            throw new IllegalArgumentException("federation peer key is not Ed25519", exception);
        }
        byte[] calculated = sha256(encoded);
        keyIdSha256 = Objects.requireNonNull(keyIdSha256, "keyIdSha256").clone();
        if (keyIdSha256.length != 32 || !MessageDigest.isEqual(calculated, keyIdSha256)) {
            throw new IllegalArgumentException("federation peer key id does not match its public key");
        }
        capabilities = Set.copyOf(Objects.requireNonNull(capabilities, "capabilities"));
        if (capabilities.isEmpty() || capabilities.size() > FederationPeerCapability.values().length) {
            throw new IllegalArgumentException("federation peer requires explicit least-privilege capabilities");
        }
    }

    @Override
    public byte[] keyIdSha256() {
        return keyIdSha256.clone();
    }

    public String keyIdHex() {
        return HexFormat.of().formatHex(keyIdSha256);
    }

    public boolean allows(FederationPeerCapability capability) {
        return capabilities.contains(Objects.requireNonNull(capability, "capability"));
    }

    static void requireNetworkId(String value) {
        Objects.requireNonNull(value, "networkId");
        if (value.isBlank() || value.length() > ProtocolConstants.MAX_FEDERATION_ID_CHARS
                || !value.matches("[A-Za-z0-9][A-Za-z0-9._:-]*")) {
            throw new IllegalArgumentException("invalid federation network id");
        }
    }

    static byte[] sha256(byte[] value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(Objects.requireNonNull(value, "value"));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }
}
