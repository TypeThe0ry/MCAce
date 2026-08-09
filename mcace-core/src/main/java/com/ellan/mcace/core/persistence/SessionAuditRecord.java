package com.ellan.mcace.core.persistence;

import com.ellan.mcace.core.session.SessionStage;
import com.ellan.mcace.protocol.generated.LoaderType;
import com.ellan.mcace.protocol.generated.TrustLevel;
import com.ellan.mcace.sdk.AdmissionStatus;
import com.ellan.mcace.sdk.RiskBand;
import java.time.Instant;
import java.util.Objects;
import java.util.UUID;

public record SessionAuditRecord(
        String sessionId,
        UUID playerId,
        String serverId,
        String policyVersion,
        long policySequence,
        SessionStage stage,
        TrustLevel trustLevel,
        AdmissionStatus admissionStatus,
        int riskScore,
        RiskBand riskBand,
        String clientBuildId,
        String minecraftVersion,
        LoaderType loader,
        Instant startedAt,
        Instant updatedAt,
        Instant expiresAt) {
    public SessionAuditRecord {
        sessionId = requireText(sessionId, "sessionId");
        Objects.requireNonNull(playerId, "playerId");
        serverId = requireText(serverId, "serverId");
        policyVersion = requireText(policyVersion, "policyVersion");
        Objects.requireNonNull(stage, "stage");
        Objects.requireNonNull(trustLevel, "trustLevel");
        Objects.requireNonNull(admissionStatus, "admissionStatus");
        Objects.requireNonNull(riskBand, "riskBand");
        clientBuildId = Objects.requireNonNull(clientBuildId, "clientBuildId");
        minecraftVersion = Objects.requireNonNull(minecraftVersion, "minecraftVersion");
        Objects.requireNonNull(loader, "loader");
        Objects.requireNonNull(startedAt, "startedAt");
        Objects.requireNonNull(updatedAt, "updatedAt");
        Objects.requireNonNull(expiresAt, "expiresAt");
        if (policySequence <= 0 || riskScore < 0 || updatedAt.isBefore(startedAt) || expiresAt.isBefore(startedAt)) {
            throw new IllegalArgumentException("invalid session audit record");
        }
    }

    private static String requireText(String value, String name) {
        Objects.requireNonNull(value, name);
        if (value.isBlank()) throw new IllegalArgumentException(name + " must not be blank");
        return value;
    }
}
