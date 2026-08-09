CREATE TABLE IF NOT EXISTS mcace_audit_anchor_head (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    last_sequence BIGINT NOT NULL CHECK (last_sequence >= 0),
    last_hash BYTEA NOT NULL CHECK (octet_length(last_hash) = 32),
    last_created_at TIMESTAMPTZ NULL
)

-- MCAce statement
INSERT INTO mcace_audit_anchor_head(singleton, last_sequence, last_hash, last_created_at)
VALUES (TRUE, 0, decode(repeat('00', 32), 'hex'), NULL)
ON CONFLICT (singleton) DO NOTHING

-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_audit_anchors (
    sequence BIGINT PRIMARY KEY CHECK (sequence > 0),
    anchor_id UUID NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    evidence_sequence BIGINT NOT NULL CHECK (evidence_sequence >= 0),
    evidence_chain_sha256 BYTEA NOT NULL CHECK (octet_length(evidence_chain_sha256) = 32),
    revocation_count BIGINT NOT NULL CHECK (revocation_count >= 0),
    revocation_max_sequence BIGINT NOT NULL CHECK (revocation_max_sequence >= 0),
    revocation_feed_sha256 BYTEA NOT NULL CHECK (octet_length(revocation_feed_sha256) = 32),
    operator_audit_count BIGINT NOT NULL CHECK (operator_audit_count >= 0),
    operator_audit_sha256 BYTEA NOT NULL CHECK (octet_length(operator_audit_sha256) = 32),
    previous_anchor_sha256 BYTEA NOT NULL CHECK (octet_length(previous_anchor_sha256) = 32),
    anchor_sha256 BYTEA NOT NULL UNIQUE CHECK (octet_length(anchor_sha256) = 32),
    server_signature BYTEA NOT NULL CHECK (octet_length(server_signature) = 64),
    signer_key_id TEXT NOT NULL CHECK (length(signer_key_id) BETWEEN 1 AND 128),
    CHECK (revocation_count > 0 OR revocation_max_sequence = 0)
)

-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_audit_anchor_delivery (
    anchor_id UUID PRIMARY KEY REFERENCES mcace_audit_anchors(anchor_id) ON DELETE RESTRICT,
    lease_owner TEXT NULL CHECK (lease_owner IS NULL OR length(lease_owner) BETWEEN 1 AND 128),
    lease_until TIMESTAMPTZ NULL,
    next_attempt_at TIMESTAMPTZ NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error TEXT NOT NULL DEFAULT '' CHECK (length(last_error) <= 512),
    CHECK ((lease_owner IS NULL) = (lease_until IS NULL))
)

-- MCAce statement
CREATE INDEX IF NOT EXISTS mcace_audit_anchor_delivery_due_idx
    ON mcace_audit_anchor_delivery (next_attempt_at, lease_until)

-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_audit_anchor_publications (
    anchor_id UUID PRIMARY KEY REFERENCES mcace_audit_anchors(anchor_id) ON DELETE RESTRICT,
    destination_uri TEXT NOT NULL CHECK (length(destination_uri) BETWEEN 1 AND 2048),
    published_at TIMESTAMPTZ NOT NULL,
    receipt_reference TEXT NOT NULL CHECK (length(receipt_reference) BETWEEN 1 AND 256),
    receipt_sha256 BYTEA NOT NULL CHECK (octet_length(receipt_sha256) = 32)
)

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_audit_anchors_append_only ON mcace_audit_anchors

-- MCAce statement
CREATE TRIGGER mcace_audit_anchors_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mcace_audit_anchors
FOR EACH STATEMENT EXECUTE FUNCTION mcace_reject_append_only_mutation()

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_audit_anchor_publications_append_only ON mcace_audit_anchor_publications

-- MCAce statement
CREATE TRIGGER mcace_audit_anchor_publications_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mcace_audit_anchor_publications
FOR EACH STATEMENT EXECUTE FUNCTION mcace_reject_append_only_mutation()
