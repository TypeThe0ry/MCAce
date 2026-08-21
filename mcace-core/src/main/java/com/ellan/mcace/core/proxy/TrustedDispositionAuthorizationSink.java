package com.ellan.mcace.core.proxy;

import java.io.IOException;

/** Fail-closed durable boundary for trusted high-impact disposition authorizations. */
@FunctionalInterface
public interface TrustedDispositionAuthorizationSink {
    void append(TrustedDispositionAuthorizationRecord record) throws IOException;
}