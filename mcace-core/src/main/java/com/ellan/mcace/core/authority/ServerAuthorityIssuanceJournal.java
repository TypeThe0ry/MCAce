package com.ellan.mcace.core.authority;

import java.io.IOException;
import java.util.Optional;

/** Package boundary used to prove that issuance completed before a frame can escape. */
abstract class ServerAuthorityIssuanceJournal {
    abstract void appendAndForce(ServerAuthorityIssuanceRecord record) throws IOException;

    /** Last durably committed sequence for one exact lifecycle commitment. */
    abstract long lastSequence(String lifecycleCommitmentSha256) throws IOException;

    /**
     * Last durable sequence and its canonical observation/publication timestamps.
     *
     * <p>The default keeps package-private test journals source-compatible. The production file
     * journal overrides this method and returns the two timestamps atomically from the same
     * verified decode as the sequence.</p>
     */
    ServerAuthorityIssuanceRecovery recover(String lifecycleCommitmentSha256)
            throws IOException {
        return new ServerAuthorityIssuanceRecovery(
                lastSequence(lifecycleCommitmentSha256), Optional.empty(), Optional.empty());
    }
}
