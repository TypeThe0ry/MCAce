package com.ellan.mcace.core.persistence;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;
import org.junit.jupiter.api.Test;

final class WorkflowStateMachineTest {
    @Test
    void reviewRequiresOrderedHumanDecisionAndTerminalStatesCannotReopen() {
        assertTrue(ReviewStatus.OPEN.permits(ReviewStatus.UNDER_REVIEW));
        assertFalse(ReviewStatus.OPEN.permits(ReviewStatus.ACTION_RECOMMENDED));
        assertTrue(ReviewStatus.UNDER_REVIEW.permits(ReviewStatus.ACTION_RECOMMENDED));
        assertTrue(ReviewStatus.ACTION_RECOMMENDED.permits(ReviewStatus.CLOSED_ACTIONED));
        assertFalse(ReviewStatus.CLOSED_ACTIONED.permits(ReviewStatus.UNDER_REVIEW));
        assertFalse(ReviewStatus.CLOSED_NO_ACTION.permits(ReviewStatus.ACTION_RECOMMENDED));

        assertThrows(IllegalArgumentException.class, () -> new ReviewTransition(
                UUID.randomUUID(), 2, ReviewStatus.ACTION_RECOMMENDED,
                "corroborated evidence", "", "reviewer"));
    }

    @Test
    void appealRequiresReviewBeforeARecordedDecisionAndCannotReopen() {
        assertTrue(AppealStatus.SUBMITTED.permits(AppealStatus.UNDER_REVIEW));
        assertFalse(AppealStatus.SUBMITTED.permits(AppealStatus.GRANTED));
        assertTrue(AppealStatus.UNDER_REVIEW.permits(AppealStatus.GRANTED));
        assertTrue(AppealStatus.UNDER_REVIEW.permits(AppealStatus.UPHELD));
        assertFalse(AppealStatus.GRANTED.permits(AppealStatus.UNDER_REVIEW));
        assertFalse(AppealStatus.UPHELD.permits(AppealStatus.UNDER_REVIEW));
    }
}
