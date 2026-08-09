package com.ellan.mcace.core.evidence;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import com.ellan.mcace.protocol.ProtocolConstants;

/** Explicit bounded handoff for collected bytes; implementations own retention policy. */
@FunctionalInterface
public interface EvidenceContentStore {
    StoreResult store(EvidenceContent content) throws Exception;

    /** The signed client-visible retention disclosure this store requires on new requests. */
    default RetentionDisclosure retentionDisclosure() { return RetentionDisclosure.none(); }

    /** Extended handoff used by stores that bind encryption AAD to full evidence metadata. */
    default StoreResult store(EvidenceContent content, EvidenceStorageMetadata metadata) throws Exception {
        return store(content);
    }

    record EvidenceContent(
            UUID evidenceId,
            UUID playerId,
            String sessionId,
            String requestId,
            Instant capturedAt,
            byte[] content,
            byte[] contentSha256) {
        public EvidenceContent {
            Objects.requireNonNull(evidenceId, "evidenceId");
            Objects.requireNonNull(playerId, "playerId");
            Objects.requireNonNull(sessionId, "sessionId");
            Objects.requireNonNull(requestId, "requestId");
            Objects.requireNonNull(capturedAt, "capturedAt");
            Objects.requireNonNull(content, "content");
            Objects.requireNonNull(contentSha256, "contentSha256");
            if (content.length == 0 || contentSha256.length != 32) {
                throw new IllegalArgumentException("invalid evidence content");
            }
            content = content.clone();
            contentSha256 = contentSha256.clone();
        }

        @Override public byte[] content() { return content.clone(); }
        @Override public byte[] contentSha256() { return contentSha256.clone(); }
    }

    record StoreResult(String storageUri) {
        public StoreResult {
            Objects.requireNonNull(storageUri, "storageUri");
            if (storageUri.isBlank() || storageUri.length() > 512) {
                throw new IllegalArgumentException("invalid evidence storage URI");
            }
        }
    }

    record RetentionDisclosure(
            boolean rawContentRetained, long retentionSeconds, String retentionPolicyId, String retentionPurpose) {
        public RetentionDisclosure {
            Objects.requireNonNull(retentionPolicyId, "retentionPolicyId");
            Objects.requireNonNull(retentionPurpose, "retentionPurpose");
            if (!rawContentRetained && (retentionSeconds != 0 || !retentionPolicyId.isEmpty()
                    || !retentionPurpose.isEmpty())) {
                throw new IllegalArgumentException("non-retained content must have empty disclosure");
            }
            if (rawContentRetained && (retentionSeconds <= 0
                    || retentionSeconds > ProtocolConstants.MAX_EVIDENCE_RETENTION_SECONDS
                    || retentionPolicyId.isBlank()
                    || retentionPurpose.isBlank())) {
                throw new IllegalArgumentException("retained content requires a complete disclosure");
            }
            if (retentionPolicyId.length() > ProtocolConstants.MAX_EVIDENCE_RETENTION_POLICY_ID_CHARS
                    || retentionPurpose.length() > ProtocolConstants.MAX_EVIDENCE_RETENTION_PURPOSE_CHARS
                    || containsControl(retentionPolicyId) || containsControl(retentionPurpose)) {
                throw new IllegalArgumentException("retention disclosure is not bounded");
            }
        }

        public static RetentionDisclosure none() {
            return new RetentionDisclosure(false, 0, "", "");
        }

        private static boolean containsControl(String value) {
            return value.chars().anyMatch(Character::isISOControl);
        }
    }

    /** Discarding is explicit and never writes a private path. */
    static EvidenceContentStore discard() {
        return content -> new StoreResult("memory://mcace/evidence/" + content.evidenceId());
    }
}
