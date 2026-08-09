package com.ellan.mcace.core.proxy;

import com.ellan.mcace.protocol.generated.SignedDispositionPolicyDocument;
import com.ellan.mcace.protocol.policy.PolicyException;

/** Platform adapter boundary for acquiring the most recently published detection policy. */
@FunctionalInterface
public interface SignedDispositionPolicySource {
    SignedDispositionPolicyDocument current() throws PolicyException;
}
