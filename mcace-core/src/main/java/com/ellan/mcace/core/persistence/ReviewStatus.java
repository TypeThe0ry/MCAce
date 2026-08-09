package com.ellan.mcace.core.persistence;

import java.util.EnumSet;
import java.util.Set;

public enum ReviewStatus {
    OPEN,
    UNDER_REVIEW,
    ACTION_RECOMMENDED,
    CLOSED_NO_ACTION,
    CLOSED_ACTIONED;

    public boolean permits(ReviewStatus target) {
        return switch (this) {
            case OPEN -> Set.of(UNDER_REVIEW, CLOSED_NO_ACTION).contains(target);
            case UNDER_REVIEW -> Set.of(ACTION_RECOMMENDED, CLOSED_NO_ACTION).contains(target);
            case ACTION_RECOMMENDED -> EnumSet.of(CLOSED_ACTIONED, CLOSED_NO_ACTION).contains(target);
            case CLOSED_NO_ACTION, CLOSED_ACTIONED -> false;
        };
    }
}
