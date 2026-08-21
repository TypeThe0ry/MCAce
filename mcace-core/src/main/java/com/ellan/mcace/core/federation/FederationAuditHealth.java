package com.ellan.mcace.core.federation;

/** Content-free health summary for the federation audit boundary. */
public record FederationAuditHealth(
        boolean available,
        int pending,
        long committed,
        long failures) {
    public FederationAuditHealth {
        if (pending < 0 || committed < 0L || failures < 0L) {
            throw new IllegalArgumentException("invalid federation audit health");
        }
    }

    static FederationAuditHealth synchronousHealthy() {
        return new FederationAuditHealth(true, 0, 0L, 0L);
    }
}
