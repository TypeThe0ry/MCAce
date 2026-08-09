-- Global row lock used to serialize quota checks across Cloud instances.
CREATE TABLE IF NOT EXISTS mcace_auth_challenge_guard (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton)
)

-- MCAce statement
INSERT INTO mcace_auth_challenge_guard(singleton)
VALUES (TRUE)
ON CONFLICT (singleton) DO NOTHING

-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_auth_challenges (
    challenge_id UUID PRIMARY KEY,
    server_id TEXT NOT NULL CHECK (server_id ~ '^[A-Za-z0-9._-]{1,64}$'),
    public_key BYTEA NOT NULL CHECK (octet_length(public_key) BETWEEN 32 AND 128),
    scopes TEXT[] NOT NULL CHECK (
        cardinality(scopes) BETWEEN 1 AND 16
        AND scopes <@ ARRAY[
            'RISK_WRITE', 'EVIDENCE_WRITE', 'REVOCATION_READ', 'REVOCATION_WRITE',
            'TIMELINE_READ', 'REVIEW_WRITE', 'APPEAL_WRITE', 'POLICY_READ',
            'POLICY_WRITE', 'FEEDBACK_WRITE', 'METRICS_READ'
        ]::TEXT[]),
    signing_payload BYTEA NOT NULL CHECK (octet_length(signing_payload) BETWEEN 64 AND 1024),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (expires_at > created_at),
    CHECK (expires_at <= created_at + INTERVAL '2 minutes')
)

-- MCAce statement
CREATE INDEX IF NOT EXISTS mcace_auth_challenges_server_idx
    ON mcace_auth_challenges (server_id, expires_at)

-- MCAce statement
CREATE INDEX IF NOT EXISTS mcace_auth_challenges_expiry_idx
    ON mcace_auth_challenges (expires_at)

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_auth_challenges_no_update ON mcace_auth_challenges

-- MCAce statement
CREATE TRIGGER mcace_auth_challenges_no_update
BEFORE UPDATE OR TRUNCATE ON mcace_auth_challenges
FOR EACH STATEMENT EXECUTE FUNCTION mcace_reject_append_only_mutation()
