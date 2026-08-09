package com.ellan.mcace.storage.postgres;

import com.ellan.mcace.core.persistence.SecurityPersistenceException;

public interface AuditAnchorSigner {
    byte[] sign(byte[] anchorSha256) throws SecurityPersistenceException;
    String keyId();
}
