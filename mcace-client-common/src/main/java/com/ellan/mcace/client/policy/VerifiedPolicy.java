package com.ellan.mcace.client.policy;

import com.ellan.mcace.protocol.generated.SecurityPolicy;
import com.ellan.mcace.protocol.generated.SignedPolicyDocument;
import java.util.Objects;

public record VerifiedPolicy(
        SecurityPolicy policy,
        SignedPolicyDocument document,
        byte[] policySha256,
        long trustSequence,
        boolean delegated) {
    public VerifiedPolicy {
        Objects.requireNonNull(policy, "policy");
        Objects.requireNonNull(document, "document");
        Objects.requireNonNull(policySha256, "policySha256");
        if (policySha256.length != 32 || trustSequence < 0) {
            throw new IllegalArgumentException("policySha256 must contain 32 bytes");
        }
        policySha256 = policySha256.clone();
    }

    @Override
    public byte[] policySha256() {
        return policySha256.clone();
    }
}
