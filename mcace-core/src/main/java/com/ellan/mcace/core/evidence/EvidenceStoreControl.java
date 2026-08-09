package com.ellan.mcace.core.evidence;

import java.util.UUID;

/** Narrow administrative capability; it cannot expose content, paths, or keys. */
public interface EvidenceStoreControl {
    EvidenceStoreStatus status();
    boolean delete(UUID evidenceId) throws Exception;
    int sweepExpired(int maxDeletes) throws Exception;
}
