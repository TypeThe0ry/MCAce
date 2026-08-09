-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_sessions (
    session_id TEXT PRIMARY KEY,
    player_uuid UUID NOT NULL,
    server_id TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    policy_sequence BIGINT NOT NULL CHECK (policy_sequence > 0),
    stage TEXT NOT NULL,
    trust_level TEXT NOT NULL,
    admission_status TEXT NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0),
    risk_band TEXT NOT NULL,
    client_build_id TEXT NOT NULL,
    minecraft_version TEXT NOT NULL,
    loader TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (updated_at >= started_at),
    CHECK (expires_at >= started_at)
)

-- MCAce statement
CREATE INDEX IF NOT EXISTS mcace_sessions_player_updated_idx
    ON mcace_sessions (player_uuid, updated_at DESC)

-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_risk_events (
    event_id UUID PRIMARY KEY,
    session_id TEXT NULL REFERENCES mcace_sessions(session_id) ON DELETE RESTRICT,
    player_uuid UUID NOT NULL,
    event_type TEXT NOT NULL,
    weight INTEGER NOT NULL CHECK (weight >= 0),
    source TEXT NOT NULL,
    origin TEXT NOT NULL CHECK (origin IN ('SERVER_CONFIRMED', 'CLIENT_REPORTED', 'INFERRED', 'MISSING')),
    corroborated BOOLEAN NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    details JSONB NOT NULL,
    inserted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
)

-- MCAce statement
CREATE INDEX IF NOT EXISTS mcace_risk_events_player_time_idx
    ON mcace_risk_events (player_uuid, observed_at DESC)

-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_evidence_chain_head (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    last_sequence BIGINT NOT NULL CHECK (last_sequence >= 0),
    last_hash BYTEA NOT NULL CHECK (octet_length(last_hash) = 32)
)

-- MCAce statement
INSERT INTO mcace_evidence_chain_head(singleton, last_sequence, last_hash)
VALUES (TRUE, 0, decode(repeat('00', 32), 'hex'))
ON CONFLICT (singleton) DO NOTHING

-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_evidence_metadata (
    chain_sequence BIGINT PRIMARY KEY CHECK (chain_sequence > 0),
    evidence_id UUID NOT NULL UNIQUE,
    player_uuid UUID NOT NULL,
    session_id TEXT NULL REFERENCES mcace_sessions(session_id) ON DELETE RESTRICT,
    evidence_type TEXT NOT NULL,
    origin TEXT NOT NULL CHECK (origin IN ('SERVER_CONFIRMED', 'CLIENT_REPORTED', 'INFERRED', 'MISSING')),
    captured_at TIMESTAMPTZ NOT NULL,
    stored_at TIMESTAMPTZ NOT NULL,
    content_size BIGINT NOT NULL CHECK (content_size >= 0),
    content_sha256 BYTEA NOT NULL CHECK (octet_length(content_sha256) = 32),
    storage_uri TEXT NOT NULL,
    operator_id TEXT NOT NULL,
    previous_chain_sha256 BYTEA NOT NULL CHECK (octet_length(previous_chain_sha256) = 32),
    chain_sha256 BYTEA NOT NULL UNIQUE CHECK (octet_length(chain_sha256) = 32),
    server_signature BYTEA NOT NULL CHECK (octet_length(server_signature) > 0),
    signer_key_id TEXT NOT NULL
)

-- MCAce statement
CREATE INDEX IF NOT EXISTS mcace_evidence_player_time_idx
    ON mcace_evidence_metadata (player_uuid, captured_at DESC)

-- MCAce statement
CREATE OR REPLACE FUNCTION mcace_reject_append_only_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'MCAce append-only table % does not permit %', TG_TABLE_NAME, TG_OP
        USING ERRCODE = '55000';
END;
$$

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_risk_events_append_only ON mcace_risk_events

-- MCAce statement
CREATE TRIGGER mcace_risk_events_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mcace_risk_events
FOR EACH STATEMENT EXECUTE FUNCTION mcace_reject_append_only_mutation()

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_evidence_append_only ON mcace_evidence_metadata

-- MCAce statement
CREATE TRIGGER mcace_evidence_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mcace_evidence_metadata
FOR EACH STATEMENT EXECUTE FUNCTION mcace_reject_append_only_mutation()
