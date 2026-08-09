package com.ellan.mcace.core.persistence;

import java.util.Set;

public enum AppealStatus {
    SUBMITTED,
    UNDER_REVIEW,
    GRANTED,
    UPHELD;

    public boolean permits(AppealStatus target) {
        return switch (this) {
            case SUBMITTED -> target == UNDER_REVIEW;
            case UNDER_REVIEW -> Set.of(GRANTED, UPHELD).contains(target);
            case GRANTED, UPHELD -> false;
        };
    }
}
