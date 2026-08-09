package com.ellan.mcace.core.persistence;

public enum PolicyRolloutStage {
    BASELINE,
    SHADOW,
    CANARY,
    BROAD,
    FULL,
    PAUSED,
    ROLLED_BACK;

    public boolean assignsCandidate() {
        return this == CANARY || this == BROAD || this == FULL;
    }
}
