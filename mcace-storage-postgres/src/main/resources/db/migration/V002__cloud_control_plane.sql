CREATE SEQUENCE IF NOT EXISTS mcace_revocation_sequence AS BIGINT START WITH 1 INCREMENT BY 1 NO CYCLE

-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_revocations (
    sequence BIGINT PRIMARY KEY CHECK (sequence > 0),
    revocation_id UUID NOT NULL UNIQUE,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    effective_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NULL,
    actor_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    payload_sha256 BYTEA NOT NULL CHECK (octet_length(payload_sha256) = 32),
    server_signature BYTEA NOT NULL CHECK (octet_length(server_signature) > 0),
    signer_key_id TEXT NOT NULL,
    CHECK (expires_at IS NULL OR expires_at > effective_at)
)

-- MCAce statement
CREATE INDEX IF NOT EXISTS mcace_revocations_subject_idx
    ON mcace_revocations (subject_type, subject_id, sequence DESC)

-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_operator_audit (
    audit_id UUID PRIMARY KEY,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    details JSONB NOT NULL,
    inserted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
)

-- MCAce statement
CREATE INDEX IF NOT EXISTS mcace_operator_audit_time_idx
    ON mcace_operator_audit (occurred_at DESC, audit_id)

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_revocations_append_only ON mcace_revocations

-- MCAce statement
CREATE TRIGGER mcace_revocations_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mcace_revocations
FOR EACH STATEMENT EXECUTE FUNCTION mcace_reject_append_only_mutation()

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_operator_audit_append_only ON mcace_operator_audit

-- MCAce statement
CREATE TRIGGER mcace_operator_audit_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mcace_operator_audit
FOR EACH STATEMENT EXECUTE FUNCTION mcace_reject_append_only_mutation()
