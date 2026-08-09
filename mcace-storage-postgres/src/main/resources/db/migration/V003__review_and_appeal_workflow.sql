CREATE TABLE IF NOT EXISTS mcace_review_cases (
    case_id UUID PRIMARY KEY,
    player_uuid UUID NOT NULL,
    title TEXT NOT NULL CHECK (char_length(title) BETWEEN 1 AND 128),
    reason TEXT NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 4096),
    created_by TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'OPEN', 'UNDER_REVIEW', 'ACTION_RECOMMENDED', 'CLOSED_NO_ACTION', 'CLOSED_ACTIONED')),
    recommendation TEXT NOT NULL DEFAULT '',
    resolution TEXT NOT NULL DEFAULT '',
    version BIGINT NOT NULL CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (updated_at >= created_at),
    CHECK (status <> 'ACTION_RECOMMENDED' OR char_length(recommendation) > 0)
)

-- MCAce statement
CREATE INDEX IF NOT EXISTS mcace_review_cases_player_time_idx
    ON mcace_review_cases (player_uuid, updated_at DESC, case_id)

-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_review_transitions (
    transition_id UUID PRIMARY KEY,
    case_id UUID NOT NULL REFERENCES mcace_review_cases(case_id) ON DELETE RESTRICT,
    from_status TEXT NULL,
    to_status TEXT NOT NULL,
    resulting_version BIGINT NOT NULL CHECK (resulting_version > 0),
    actor_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    recommendation TEXT NOT NULL DEFAULT '',
    occurred_at TIMESTAMPTZ NOT NULL,
    UNIQUE (case_id, resulting_version)
)

-- MCAce statement
CREATE INDEX IF NOT EXISTS mcace_review_transitions_case_idx
    ON mcace_review_transitions (case_id, resulting_version)

-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_appeals (
    appeal_id UUID PRIMARY KEY,
    case_id UUID NOT NULL UNIQUE REFERENCES mcace_review_cases(case_id) ON DELETE RESTRICT,
    player_uuid UUID NOT NULL,
    statement TEXT NOT NULL CHECK (char_length(statement) BETWEEN 1 AND 8192),
    submitted_by TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('SUBMITTED', 'UNDER_REVIEW', 'GRANTED', 'UPHELD')),
    decision_reason TEXT NOT NULL DEFAULT '',
    version BIGINT NOT NULL CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (updated_at >= created_at),
    CHECK (status NOT IN ('GRANTED', 'UPHELD') OR char_length(decision_reason) > 0)
)

-- MCAce statement
CREATE INDEX IF NOT EXISTS mcace_appeals_player_time_idx
    ON mcace_appeals (player_uuid, updated_at DESC, appeal_id)

-- MCAce statement
CREATE TABLE IF NOT EXISTS mcace_appeal_transitions (
    transition_id UUID PRIMARY KEY,
    appeal_id UUID NOT NULL REFERENCES mcace_appeals(appeal_id) ON DELETE RESTRICT,
    from_status TEXT NULL,
    to_status TEXT NOT NULL,
    resulting_version BIGINT NOT NULL CHECK (resulting_version > 0),
    actor_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    UNIQUE (appeal_id, resulting_version)
)

-- MCAce statement
CREATE INDEX IF NOT EXISTS mcace_appeal_transitions_appeal_idx
    ON mcace_appeal_transitions (appeal_id, resulting_version)

-- MCAce statement
CREATE OR REPLACE FUNCTION mcace_validate_review_snapshot_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'MCAce review version must increment by one' USING ERRCODE = '23000';
    END IF;
    IF NOT (
        (OLD.status = 'OPEN' AND NEW.status IN ('UNDER_REVIEW', 'CLOSED_NO_ACTION')) OR
        (OLD.status = 'UNDER_REVIEW' AND NEW.status IN ('ACTION_RECOMMENDED', 'CLOSED_NO_ACTION')) OR
        (OLD.status = 'ACTION_RECOMMENDED' AND NEW.status IN ('CLOSED_ACTIONED', 'CLOSED_NO_ACTION'))
    ) THEN
        RAISE EXCEPTION 'MCAce review transition % -> % is invalid', OLD.status, NEW.status
            USING ERRCODE = '23000';
    END IF;
    RETURN NEW;
END;
$$

-- MCAce statement
CREATE OR REPLACE FUNCTION mcace_validate_appeal_snapshot_update()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.version <> OLD.version + 1 THEN
        RAISE EXCEPTION 'MCAce appeal version must increment by one' USING ERRCODE = '23000';
    END IF;
    IF NOT (
        (OLD.status = 'SUBMITTED' AND NEW.status = 'UNDER_REVIEW') OR
        (OLD.status = 'UNDER_REVIEW' AND NEW.status IN ('GRANTED', 'UPHELD'))
    ) THEN
        RAISE EXCEPTION 'MCAce appeal transition % -> % is invalid', OLD.status, NEW.status
            USING ERRCODE = '23000';
    END IF;
    RETURN NEW;
END;
$$

-- MCAce statement
CREATE OR REPLACE FUNCTION mcace_require_review_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM mcace_review_transitions
        WHERE case_id = NEW.case_id AND resulting_version = NEW.version AND to_status = NEW.status
    ) THEN
        RAISE EXCEPTION 'MCAce review snapshot has no matching transition' USING ERRCODE = '23000';
    END IF;
    RETURN NULL;
END;
$$

-- MCAce statement
CREATE OR REPLACE FUNCTION mcace_require_appeal_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM mcace_appeal_transitions
        WHERE appeal_id = NEW.appeal_id AND resulting_version = NEW.version AND to_status = NEW.status
    ) THEN
        RAISE EXCEPTION 'MCAce appeal snapshot has no matching transition' USING ERRCODE = '23000';
    END IF;
    RETURN NULL;
END;
$$

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_review_cases_validate_update ON mcace_review_cases

-- MCAce statement
CREATE TRIGGER mcace_review_cases_validate_update
BEFORE UPDATE ON mcace_review_cases
FOR EACH ROW EXECUTE FUNCTION mcace_validate_review_snapshot_update()

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_appeals_validate_update ON mcace_appeals

-- MCAce statement
CREATE TRIGGER mcace_appeals_validate_update
BEFORE UPDATE ON mcace_appeals
FOR EACH ROW EXECUTE FUNCTION mcace_validate_appeal_snapshot_update()

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_review_cases_require_transition ON mcace_review_cases

-- MCAce statement
CREATE CONSTRAINT TRIGGER mcace_review_cases_require_transition
AFTER INSERT OR UPDATE ON mcace_review_cases
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION mcace_require_review_transition()

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_appeals_require_transition ON mcace_appeals

-- MCAce statement
CREATE CONSTRAINT TRIGGER mcace_appeals_require_transition
AFTER INSERT OR UPDATE ON mcace_appeals
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION mcace_require_appeal_transition()

-- MCAce statement
CREATE OR REPLACE FUNCTION mcace_reject_delete_or_truncate()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'MCAce workflow table % does not permit %', TG_TABLE_NAME, TG_OP
        USING ERRCODE = '55000';
END;
$$

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_review_cases_no_delete ON mcace_review_cases

-- MCAce statement
CREATE TRIGGER mcace_review_cases_no_delete
BEFORE DELETE OR TRUNCATE ON mcace_review_cases
FOR EACH STATEMENT EXECUTE FUNCTION mcace_reject_delete_or_truncate()

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_appeals_no_delete ON mcace_appeals

-- MCAce statement
CREATE TRIGGER mcace_appeals_no_delete
BEFORE DELETE OR TRUNCATE ON mcace_appeals
FOR EACH STATEMENT EXECUTE FUNCTION mcace_reject_delete_or_truncate()

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_review_transitions_append_only ON mcace_review_transitions

-- MCAce statement
CREATE TRIGGER mcace_review_transitions_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mcace_review_transitions
FOR EACH STATEMENT EXECUTE FUNCTION mcace_reject_append_only_mutation()

-- MCAce statement
DROP TRIGGER IF EXISTS mcace_appeal_transitions_append_only ON mcace_appeal_transitions

-- MCAce statement
CREATE TRIGGER mcace_appeal_transitions_append_only
BEFORE UPDATE OR DELETE OR TRUNCATE ON mcace_appeal_transitions
FOR EACH STATEMENT EXECUTE FUNCTION mcace_reject_append_only_mutation()
