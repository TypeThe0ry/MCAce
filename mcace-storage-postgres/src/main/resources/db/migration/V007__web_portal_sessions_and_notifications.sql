ALTER TABLE mcace_auth_challenges
    DROP CONSTRAINT IF EXISTS mcace_auth_challenges_scopes_check

-- MCAce statement
ALTER TABLE mcace_auth_challenges
    ADD CONSTRAINT mcace_auth_challenges_scopes_check CHECK (
        cardinality(scopes) BETWEEN 1 AND 16
        AND scopes <@ ARRAY[
            'RISK_WRITE', 'EVIDENCE_WRITE', 'REVOCATION_READ', 'REVOCATION_WRITE',
            'TIMELINE_READ', 'REVIEW_WRITE', 'APPEAL_WRITE', 'POLICY_READ',
            'POLICY_WRITE', 'FEEDBACK_WRITE', 'METRICS_READ',
            'WEB_OPERATOR_SESSION_WRITE', 'WEB_PLAYER_SESSION_WRITE'
        ]::TEXT[])

-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_web_handoffs (
    handoff_id UUID PRIMARY KEY,
    secret_sha256 BYTEA NOT NULL CHECK (octet_length(secret_sha256) = 32),
    principal_type TEXT NOT NULL CHECK (principal_type IN ('OPERATOR', 'PLAYER')),
    subject_id TEXT NOT NULL CHECK (char_length(subject_id) BETWEEN 1 AND 128),
    roles TEXT[] NOT NULL CHECK (
        cardinality(roles) BETWEEN 1 AND 4
        AND roles <@ ARRAY[
            'OPERATOR_VIEWER', 'OPERATOR_REVIEWER', 'OPERATOR_POLICY_ADMIN', 'PLAYER'
        ]::TEXT[]),
    redirect_path TEXT NOT NULL CHECK (
        char_length(redirect_path) BETWEEN 1 AND 128
        AND redirect_path LIKE '/%'
        AND redirect_path NOT LIKE '//%'
        AND position('\\' IN redirect_path) = 0
        AND position('?' IN redirect_path) = 0
        AND position('#' IN redirect_path) = 0),
    created_by TEXT NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (expires_at > created_at),
    CHECK (expires_at <= created_at + INTERVAL '10 minutes'),
    CHECK (
        (principal_type = 'PLAYER' AND roles = ARRAY['PLAYER']::TEXT[]) OR
        (principal_type = 'OPERATOR'
            AND roles @> ARRAY['OPERATOR_VIEWER']::TEXT[]
            AND NOT roles && ARRAY['PLAYER']::TEXT[]))
)

-- MCAce statement
CREATE INDEX IF NOT EXISTS mcace_web_handoffs_expiry_idx
    ON mcace_web_handoffs (expires_at)

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_web_handoffs_no_update ON mcace_web_handoffs

-- MCAce statement
CREATE TRIGGER mcace_web_handoffs_no_update
BEFORE UPDATE OR TRUNCATE ON mcace_web_handoffs
FOR EACH STATEMENT EXECUTE FUNCTION mcace_reject_append_only_mutation()

-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_web_sessions (
    session_id UUID PRIMARY KEY,
    secret_sha256 BYTEA NOT NULL UNIQUE CHECK (octet_length(secret_sha256) = 32),
    principal_type TEXT NOT NULL CHECK (principal_type IN ('OPERATOR', 'PLAYER')),
    subject_id TEXT NOT NULL CHECK (char_length(subject_id) BETWEEN 1 AND 128),
    roles TEXT[] NOT NULL CHECK (
        cardinality(roles) BETWEEN 1 AND 4
        AND roles <@ ARRAY[
            'OPERATOR_VIEWER', 'OPERATOR_REVIEWER', 'OPERATOR_POLICY_ADMIN', 'PLAYER'
        ]::TEXT[]),
    created_by TEXT NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (expires_at > created_at),
    CHECK (expires_at <= created_at + INTERVAL '12 hours'),
    CHECK (
        (principal_type = 'PLAYER' AND roles = ARRAY['PLAYER']::TEXT[]) OR
        (principal_type = 'OPERATOR'
            AND roles @> ARRAY['OPERATOR_VIEWER']::TEXT[]
            AND NOT roles && ARRAY['PLAYER']::TEXT[]))
)

-- MCAce statement
CREATE INDEX IF NOT EXISTS mcace_web_sessions_expiry_idx
    ON mcace_web_sessions (expires_at)

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_web_sessions_no_update ON mcace_web_sessions

-- MCAce statement
CREATE TRIGGER mcace_web_sessions_no_update
BEFORE UPDATE OR TRUNCATE ON mcace_web_sessions
FOR EACH STATEMENT EXECUTE FUNCTION mcace_reject_append_only_mutation()

-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_player_notifications (
    notification_id UUID PRIMARY KEY,
    player_uuid UUID NOT NULL,
    type TEXT NOT NULL CHECK (char_length(type) BETWEEN 1 AND 64),
    subject_id TEXT NOT NULL CHECK (char_length(subject_id) BETWEEN 1 AND 128),
    title TEXT NOT NULL CHECK (char_length(title) BETWEEN 1 AND 160),
    message TEXT NOT NULL CHECK (char_length(message) BETWEEN 1 AND 2000),
    created_by TEXT NOT NULL CHECK (char_length(created_by) BETWEEN 1 AND 128),
    created_at TIMESTAMPTZ NOT NULL
)

-- MCAce statement
CREATE INDEX IF NOT EXISTS mcace_player_notifications_player_time_idx
    ON mcace_player_notifications (player_uuid, created_at DESC, notification_id)

-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_player_notification_reads (
    notification_id UUID PRIMARY KEY
        REFERENCES mcace_player_notifications(notification_id) ON DELETE RESTRICT,
    player_uuid UUID NOT NULL,
    read_at TIMESTAMPTZ NOT NULL
)

-- MCAce statement
CREATE OR REPLACE FUNCTION mcace_validate_notification_read()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    expected_player UUID;
    notification_created_at TIMESTAMPTZ;
BEGIN
    SELECT player_uuid, created_at
    INTO expected_player, notification_created_at
    FROM mcace_player_notifications
    WHERE notification_id = NEW.notification_id;
    IF expected_player IS NULL OR expected_player <> NEW.player_uuid THEN
        RAISE EXCEPTION 'MCAce notification does not belong to player'
            USING ERRCODE = '23000';
    END IF;
    IF NEW.read_at < notification_created_at THEN
        RAISE EXCEPTION 'MCAce notification read precedes creation'
            USING ERRCODE = '23000';
    END IF;
    RETURN NEW;
END;
$$

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_player_notification_reads_validate
    ON mcace_player_notification_reads

-- MCAce statement
CREATE TRIGGER mcace_player_notification_reads_validate
BEFORE INSERT ON mcace_player_notification_reads
FOR EACH ROW EXECUTE FUNCTION mcace_validate_notification_read()

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_player_notifications_append_only
    ON mcace_player_notifications

-- MCAce statement
CREATE TRIGGER mcace_player_notifications_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mcace_player_notifications
FOR EACH STATEMENT EXECUTE FUNCTION mcace_reject_append_only_mutation()

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_player_notification_reads_append_only
    ON mcace_player_notification_reads

-- MCAce statement
CREATE TRIGGER mcace_player_notification_reads_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mcace_player_notification_reads
FOR EACH STATEMENT EXECUTE FUNCTION mcace_reject_append_only_mutation()
