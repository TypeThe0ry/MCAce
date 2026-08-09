package com.ellan.mcace.storage.postgres;

import com.ellan.mcace.core.persistence.SecurityPersistenceException;

public interface RevocationSigner {
    byte[] sign(byte[] payloadSha256) throws SecurityPersistenceException;

    String keyId();
}
