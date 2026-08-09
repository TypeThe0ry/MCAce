package com.ellan.mcace.core.evidence;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.generated.EvidenceCaptureScope;
import com.ellan.mcace.protocol.generated.EvidenceType;
import java.time.Duration;
import java.util.List;
import java.util.Objects;

/** Operator-controlled, bounded inputs used to create one evidence request. */
public record EvidenceRequestSpec(
        EvidenceType type,
        EvidenceCaptureScope captureScope,
        List<String> allowedRelativePaths,
        String caseId,
        Duration ttl,
        EvidenceContentStore.RetentionDisclosure retentionDisclosure) {
    public EvidenceRequestSpec(
            EvidenceType type, EvidenceCaptureScope captureScope, List<String> allowedRelativePaths,
            String caseId, Duration ttl) {
        this(type, captureScope, allowedRelativePaths, caseId, ttl, EvidenceContentStore.RetentionDisclosure.none());
    }

    public EvidenceRequestSpec {
        Objects.requireNonNull(type, "type");
        Objects.requireNonNull(captureScope, "captureScope");
        Objects.requireNonNull(allowedRelativePaths, "allowedRelativePaths");
        caseId = Objects.requireNonNull(caseId, "caseId");
        ttl = Objects.requireNonNull(ttl, "ttl");
        retentionDisclosure = Objects.requireNonNull(retentionDisclosure, "retentionDisclosure");
        if (retentionDisclosure.rawContentRetained()
                && captureScope != EvidenceCaptureScope.GAME_RENDER_FRAME) {
            throw new IllegalArgumentException("raw retention is limited to game render frames");
        }
        if (type == EvidenceType.EVIDENCE_UNSPECIFIED || type == EvidenceType.UNRECOGNIZED
                || captureScope == EvidenceCaptureScope.EVIDENCE_CAPTURE_SCOPE_UNSPECIFIED
                || captureScope == EvidenceCaptureScope.UNRECOGNIZED
                || caseId.isBlank() || caseId.length() > 128
                || ttl.isZero() || ttl.isNegative() || ttl.compareTo(ProtocolConstants.MAX_EVIDENCE_REQUEST_TTL) > 0
                || allowedRelativePaths.size() > 64) {
            throw new IllegalArgumentException("invalid evidence request specification");
        }
        for (String path : allowedRelativePaths) {
            if (path == null || path.isBlank() || path.length() > 256
                    || path.startsWith("/") || path.contains("\\") || path.contains(":")
                    || path.equals("..") || path.startsWith("../") || path.contains("/../")) {
                throw new IllegalArgumentException("invalid evidence request path");
            }
        }
        allowedRelativePaths = List.copyOf(allowedRelativePaths);
    }

    public static EvidenceRequestSpec screenshot(EvidenceCaptureScope scope, String caseId) {
        return new EvidenceRequestSpec(
                EvidenceType.SCREENSHOT, scope, List.of(), caseId,
                ProtocolConstants.MAX_EVIDENCE_REQUEST_TTL,
                EvidenceContentStore.RetentionDisclosure.none());
    }

    public static EvidenceRequestSpec retainedScreenshot(
            EvidenceCaptureScope scope, String caseId, Duration ttl,
            long retentionSeconds, String retentionPolicyId, String retentionPurpose) {
        if (scope != EvidenceCaptureScope.GAME_RENDER_FRAME) {
            throw new IllegalArgumentException("raw retention is limited to game render frames");
        }
        return new EvidenceRequestSpec(
                EvidenceType.SCREENSHOT, scope, List.of(), caseId, ttl,
                new EvidenceContentStore.RetentionDisclosure(
                        true, retentionSeconds, retentionPolicyId, retentionPurpose));
    }
}
