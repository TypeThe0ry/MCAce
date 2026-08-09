CREATE TABLE IF NOT EXISTS mcace_risk_policy_releases (
    policy_id UUID PRIMARY KEY,
    version TEXT NOT NULL UNIQUE,
    watch_threshold INTEGER NOT NULL CHECK (watch_threshold >= 0),
    restricted_threshold INTEGER NOT NULL,
    investigation_threshold INTEGER NOT NULL,
    description TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    release_sha256 BYTEA NOT NULL UNIQUE CHECK (octet_length(release_sha256) = 32),
    CHECK (restricted_threshold > watch_threshold),
    CHECK (investigation_threshold > restricted_threshold)
)

-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_risk_policy_weights (
    policy_id UUID NOT NULL REFERENCES mcace_risk_policy_releases(policy_id) ON DELETE RESTRICT,
    event_type TEXT NOT NULL,
    weight INTEGER NOT NULL CHECK (weight >= 0),
    PRIMARY KEY (policy_id, event_type)
)

-- MCAce statement
CREATE SEQUENCE IF NOT EXISTS mcace_policy_rollout_sequence AS BIGINT START WITH 1 INCREMENT BY 1 NO CYCLE

-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_policy_rollouts (
    sequence BIGINT PRIMARY KEY CHECK (sequence > 0),
    rollout_id UUID NOT NULL UNIQUE,
    policy_id UUID NOT NULL REFERENCES mcace_risk_policy_releases(policy_id) ON DELETE RESTRICT,
    stage TEXT NOT NULL CHECK (stage IN ('SHADOW', 'CANARY', 'BROAD', 'FULL', 'PAUSED', 'ROLLED_BACK')),
    percentage INTEGER NOT NULL CHECK (percentage BETWEEN 0 AND 100),
    reason TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CHECK (
        (stage IN ('SHADOW', 'PAUSED', 'ROLLED_BACK') AND percentage = 0) OR
        (stage = 'CANARY' AND percentage BETWEEN 1 AND 25) OR
        (stage = 'BROAD' AND percentage BETWEEN 26 AND 99) OR
        (stage = 'FULL' AND percentage = 100)
    )
)

-- MCAce statement
CREATE INDEX IF NOT EXISTS mcace_policy_rollouts_policy_idx
    ON mcace_policy_rollouts (policy_id, sequence DESC)

-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_risk_policy_evaluations (
    event_id UUID PRIMARY KEY REFERENCES mcace_risk_events(event_id) ON DELETE RESTRICT,
    applied_policy_version TEXT NOT NULL,
    baseline_policy_version TEXT NOT NULL,
    candidate_policy_version TEXT NOT NULL DEFAULT '',
    assigned_weight INTEGER NOT NULL CHECK (assigned_weight >= 0),
    baseline_weight INTEGER NOT NULL CHECK (baseline_weight >= 0),
    candidate_weight INTEGER NULL CHECK (candidate_weight IS NULL OR candidate_weight >= 0),
    rollout_id UUID NULL,
    stage TEXT NOT NULL,
    cohort_bucket INTEGER NOT NULL CHECK (cohort_bucket BETWEEN 0 AND 9999),
    evaluated_at TIMESTAMPTZ NOT NULL,
    CHECK ((candidate_policy_version = '') = (candidate_weight IS NULL)),
    CHECK ((candidate_policy_version = '') = (rollout_id IS NULL))
)

-- MCAce statement
CREATE INDEX IF NOT EXISTS mcace_risk_policy_evaluations_policy_time_idx
    ON mcace_risk_policy_evaluations (applied_policy_version, evaluated_at DESC)

-- MCAce statement
CREATE INDEX IF NOT EXISTS mcace_risk_policy_evaluations_candidate_time_idx
    ON mcace_risk_policy_evaluations (candidate_policy_version, evaluated_at DESC)

-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_risk_feedback (
    feedback_id UUID PRIMARY KEY,
    event_id UUID NOT NULL REFERENCES mcace_risk_events(event_id) ON DELETE RESTRICT,
    review_case_id UUID NOT NULL REFERENCES mcace_review_cases(case_id) ON DELETE RESTRICT,
    label TEXT NOT NULL CHECK (label IN ('CONFIRMED_SIGNAL', 'FALSE_POSITIVE', 'INCONCLUSIVE')),
    notes TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    inserted_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (event_id, review_case_id)
)

-- MCAce statement
CREATE INDEX IF NOT EXISTS mcace_risk_feedback_event_time_idx
    ON mcace_risk_feedback (event_id, occurred_at DESC, feedback_id)

-- MCAce statement
CREATE OR REPLACE FUNCTION mcace_require_complete_policy_weights()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF (SELECT count(*) FROM mcace_risk_policy_weights WHERE policy_id = NEW.policy_id) <> 9 THEN
        RAISE EXCEPTION 'MCAce policy release must define all risk event weights'
            USING ERRCODE = '23000';
    END IF;
    RETURN NULL;
END;
$$

-- MCAce statement
CREATE OR REPLACE FUNCTION mcace_validate_policy_rollout_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    current_stage TEXT;
    current_percentage INTEGER;
    global_policy UUID;
    global_stage TEXT;
    permitted BOOLEAN := FALSE;
BEGIN
    PERFORM pg_advisory_xact_lock(5567361424287171);
    IF NEW.sequence <= COALESCE((SELECT max(sequence) FROM mcace_policy_rollouts), 0) THEN
        RAISE EXCEPTION 'MCAce policy rollout sequence must increase monotonically'
            USING ERRCODE = '23000';
    END IF;
    SELECT stage, percentage INTO current_stage, current_percentage
    FROM mcace_policy_rollouts WHERE policy_id = NEW.policy_id
    ORDER BY sequence DESC LIMIT 1;
    SELECT policy_id, stage INTO global_policy, global_stage
    FROM mcace_policy_rollouts ORDER BY sequence DESC LIMIT 1;

    IF global_policy IS NOT NULL AND global_policy <> NEW.policy_id
       AND global_stage IN ('SHADOW', 'CANARY', 'BROAD') THEN
        RAISE EXCEPTION 'another MCAce policy candidate is already in rollout'
            USING ERRCODE = '23000';
    END IF;

    IF current_stage IS NULL THEN
        permitted := NEW.stage = 'SHADOW';
    ELSIF current_stage = 'SHADOW' THEN
        permitted := NEW.stage IN ('CANARY', 'PAUSED', 'ROLLED_BACK');
    ELSIF current_stage = 'CANARY' THEN
        permitted := (NEW.stage = 'CANARY' AND NEW.percentage >= current_percentage)
            OR NEW.stage IN ('BROAD', 'PAUSED', 'ROLLED_BACK');
    ELSIF current_stage = 'BROAD' THEN
        permitted := (NEW.stage = 'BROAD' AND NEW.percentage >= current_percentage)
            OR NEW.stage IN ('FULL', 'PAUSED', 'ROLLED_BACK');
    ELSIF current_stage = 'PAUSED' THEN
        permitted := NEW.stage IN ('SHADOW', 'ROLLED_BACK');
    END IF;

    IF NOT permitted THEN
        RAISE EXCEPTION 'invalid MCAce policy rollout transition % -> %', current_stage, NEW.stage
            USING ERRCODE = '23000';
    END IF;
    RETURN NEW;
END;
$$

-- MCAce statement
CREATE OR REPLACE FUNCTION mcace_validate_risk_feedback_insert()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    risk_player UUID;
    review_player UUID;
    review_status TEXT;
    appeal_status TEXT;
BEGIN
    SELECT re.player_uuid, rc.player_uuid, rc.status, COALESCE(a.status, '')
    INTO risk_player, review_player, review_status, appeal_status
    FROM mcace_risk_events re
    CROSS JOIN mcace_review_cases rc
    LEFT JOIN mcace_appeals a ON a.case_id = rc.case_id
    WHERE re.event_id = NEW.event_id AND rc.case_id = NEW.review_case_id;
    IF risk_player IS NULL OR review_player IS NULL THEN
        RAISE EXCEPTION 'MCAce feedback references missing review data' USING ERRCODE = '23000';
    END IF;
    IF risk_player <> review_player THEN
        RAISE EXCEPTION 'MCAce feedback player mismatch' USING ERRCODE = '23000';
    END IF;
    IF NEW.label = 'FALSE_POSITIVE'
       AND review_status <> 'CLOSED_NO_ACTION' AND appeal_status <> 'GRANTED' THEN
        RAISE EXCEPTION 'false-positive feedback requires no-action closure or granted appeal'
            USING ERRCODE = '23000';
    END IF;
    IF NEW.label = 'CONFIRMED_SIGNAL'
       AND review_status NOT IN ('ACTION_RECOMMENDED', 'CLOSED_ACTIONED')
       AND appeal_status <> 'UPHELD' THEN
        RAISE EXCEPTION 'confirmed feedback requires a corroborated review outcome'
            USING ERRCODE = '23000';
    END IF;
    RETURN NEW;
END;
$$

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_risk_policy_releases_require_weights ON mcace_risk_policy_releases

-- MCAce statement
CREATE CONSTRAINT TRIGGER mcace_risk_policy_releases_require_weights
AFTER INSERT ON mcace_risk_policy_releases
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION mcace_require_complete_policy_weights()

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_policy_rollouts_validate_insert ON mcace_policy_rollouts

-- MCAce statement
CREATE TRIGGER mcace_policy_rollouts_validate_insert
BEFORE INSERT ON mcace_policy_rollouts
FOR EACH ROW EXECUTE FUNCTION mcace_validate_policy_rollout_insert()

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_risk_feedback_validate_insert ON mcace_risk_feedback

-- MCAce statement
CREATE TRIGGER mcace_risk_feedback_validate_insert
BEFORE INSERT ON mcace_risk_feedback
FOR EACH ROW EXECUTE FUNCTION mcace_validate_risk_feedback_insert()

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_risk_policy_releases_append_only ON mcace_risk_policy_releases

-- MCAce statement
CREATE TRIGGER mcace_risk_policy_releases_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mcace_risk_policy_releases
FOR EACH STATEMENT EXECUTE FUNCTION mcace_reject_append_only_mutation()

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_risk_policy_weights_append_only ON mcace_risk_policy_weights

-- MCAce statement
CREATE TRIGGER mcace_risk_policy_weights_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mcace_risk_policy_weights
FOR EACH STATEMENT EXECUTE FUNCTION mcace_reject_append_only_mutation()

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_policy_rollouts_append_only ON mcace_policy_rollouts

-- MCAce statement
CREATE TRIGGER mcace_policy_rollouts_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mcace_policy_rollouts
FOR EACH STATEMENT EXECUTE FUNCTION mcace_reject_append_only_mutation()

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_risk_policy_evaluations_append_only ON mcace_risk_policy_evaluations

-- MCAce statement
CREATE TRIGGER mcace_risk_policy_evaluations_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mcace_risk_policy_evaluations
FOR EACH STATEMENT EXECUTE FUNCTION mcace_reject_append_only_mutation()

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_risk_feedback_append_only ON mcace_risk_feedback

-- MCAce statement
CREATE TRIGGER mcace_risk_feedback_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mcace_risk_feedback
FOR EACH STATEMENT EXECUTE FUNCTION mcace_reject_append_only_mutation()
