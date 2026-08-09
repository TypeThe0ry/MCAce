package com.ellan.mcace.storage.postgres;

import com.ellan.mcace.core.persistence.SecurityPersistenceException;

public interface EvidenceChainSigner {
    byte[] sign(byte[] chainSha256) throws SecurityPersistenceException;

    String keyId();
}
