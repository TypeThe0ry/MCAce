package com.ellan.mcace.protocol.policy;

import com.ellan.mcace.protocol.generated.SecurityPolicy;
import java.util.Arrays;
import java.util.Objects;

public record PolicyVerification(
        SecurityPolicy policy,
        long trustSequence,
        boolean delegated,
        byte[] signerKeyIdSha256) {
    public PolicyVerification {
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(signerKeyIdSha256, "signerKeyIdSha256");
        if (trustSequence < 0 || signerKeyIdSha256.length != 32) {
            throw new IllegalArgumentException("invalid policy verification metadata");
        }
        signerKeyIdSha256 = signerKeyIdSha256.clone();
    }

    @Override
    public byte[] signerKeyIdSha256() {
        return signerKeyIdSha256.clone();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof PolicyVerification that
                && trustSequence == that.trustSequence
                && delegated == that.delegated
                && policy.equals(that.policy)
                && Arrays.equals(signerKeyIdSha256, that.signerKeyIdSha256);
    }

    @Override
    public int hashCode() {
        return 31 * Objects.hash(policy, trustSequence, delegated) + Arrays.hashCode(signerKeyIdSha256);
    }
}
