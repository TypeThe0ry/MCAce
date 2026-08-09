package com.ellan.mcace.core.policy;

import com.ellan.mcace.protocol.generated.SignedPolicyDocument;
import com.ellan.mcace.protocol.policy.PolicyException;

@FunctionalInterface
public interface SignedPolicyProvider {
    SignedPolicyDocument current() throws PolicyException;
}
