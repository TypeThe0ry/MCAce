package com.ellan.mcace.core.evidence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;
import org.junit.jupiter.api.Test;

final class EvidenceReviewCommandInputTest {
    @Test
    void reviewIsConsoleOnlyEvenWhenPlayerArgumentsAreOtherwiseValid() {
        EvidenceReviewCommandInput.Validation validation = EvidenceReviewCommandInput.validate(false,
                new String[] {"review", UUID.randomUUID().toString(), "staff-review"});
        assertEquals(EvidenceReviewCommandInput.Status.CONSOLE_ONLY, validation.status());
        assertTrue(validation.request().isEmpty());
    }

    @Test
    void acceptsOnlyBoundedConsoleReasonAndUuid() {
        UUID evidenceId = UUID.randomUUID();
        EvidenceReviewCommandInput.Validation accepted = EvidenceReviewCommandInput.validate(true,
                new String[] {"review", evidenceId.toString(), "case", "review"});
        assertEquals(EvidenceReviewCommandInput.Status.ACCEPTED, accepted.status());
        assertEquals(evidenceId, accepted.request().orElseThrow().evidenceId());
        assertEquals("case review", accepted.request().orElseThrow().reason());
        assertEquals(EvidenceReviewCommandInput.Status.INVALID_REASON,
                EvidenceReviewCommandInput.validate(true, new String[] {"review", evidenceId.toString(), "bad\nreason"}).status());
    }
}
