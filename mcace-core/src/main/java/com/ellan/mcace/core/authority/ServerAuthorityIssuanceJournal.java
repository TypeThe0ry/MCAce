package com.ellan.mcace.core.authority;

import java.io.IOException;

/** Package boundary used to prove that issuance completed before a frame can escape. */
abstract class ServerAuthorityIssuanceJournal {
    abstract void appendAndForce(ServerAuthorityIssuanceRecord record) throws IOException;

    /** Last durably committed sequence for one exact lifecycle commitment. */
    abstract long lastSequence(String lifecycleCommitmentSha256) throws IOException;
}
