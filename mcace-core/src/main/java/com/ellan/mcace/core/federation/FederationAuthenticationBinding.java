package com.ellan.mcace.core.federation;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Objects;

/**
 * Immutable target-AUTH transcript binding to one exact source-signed federation assertion.
 *
 * <p>The value is SHA-256(SignedFederationAssertion.toByteArray()). It proves causality without
 * comparing independent source and target wall clocks: the client cannot start a correctly bound
 * target authentication transcript until it possesses the completed source-signed grant.</p>
 */
public record FederationAuthenticationBinding(byte[] signedAssertionSha256) {
    public FederationAuthenticationBinding {
        signedAssertionSha256 = Objects.requireNonNull(
                signedAssertionSha256, "signedAssertionSha256").clone();
        if (signedAssertionSha256.length != 32) {
            throw new IllegalArgumentException("signedAssertionSha256 must be SHA-256");
        }
    }

    @Override
    public byte[] signedAssertionSha256() {
        return signedAssertionSha256.clone();
    }

    public boolean matches(byte[] candidate) {
        return candidate != null && MessageDigest.isEqual(signedAssertionSha256, candidate);
    }

    @Override
    public boolean equals(Object value) {
        return value instanceof FederationAuthenticationBinding other
                && MessageDigest.isEqual(signedAssertionSha256, other.signedAssertionSha256);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(signedAssertionSha256);
    }
}
