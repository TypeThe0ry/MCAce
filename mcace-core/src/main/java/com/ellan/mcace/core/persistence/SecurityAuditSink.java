package com.ellan.mcace.core.persistence;

public interface SecurityAuditSink {
    void upsertSession(SessionAuditRecord session) throws SecurityPersistenceException;

    void appendRiskEvent(RiskEventAuditRecord event) throws SecurityPersistenceException;

    StoredEvidenceMetadata appendEvidence(EvidenceMetadataDraft evidence) throws SecurityPersistenceException;

    static SecurityAuditSink noop() {
        return NoOpHolder.INSTANCE;
    }

    final class NoOpHolder {
        private static final SecurityAuditSink INSTANCE = new SecurityAuditSink() {
            @Override public void upsertSession(SessionAuditRecord session) { }
            @Override public void appendRiskEvent(RiskEventAuditRecord event) { }
            @Override public StoredEvidenceMetadata appendEvidence(EvidenceMetadataDraft evidence) {
                throw new UnsupportedOperationException("evidence persistence is disabled");
            }
        };

        private NoOpHolder() { }
    }
}
