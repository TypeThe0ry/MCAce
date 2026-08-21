package com.ellan.mcace.core.authority;

/**
 * Signals that an in-memory issuance lease no longer follows the durable journal sequence.
 *
 * <p>No record is appended for this failure. Callers must discard the stale lifecycle state and
 * recover it from the journal before preparing another issuance.</p>
 */
public final class AuthoritySequenceMismatchException extends AuthorityProtocolException {
    private static final long serialVersionUID = 1L;

    AuthoritySequenceMismatchException() {
        super("authority issuance lease does not follow the durable sequence");
    }
}
