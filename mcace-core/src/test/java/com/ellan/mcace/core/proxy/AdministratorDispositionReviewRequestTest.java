package com.ellan.mcace.core.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.ellan.mcace.core.disposition.ArtifactType;
import com.ellan.mcace.core.disposition.Confidence;
import com.ellan.mcace.core.disposition.ObservationOrigin;
import org.junit.jupiter.api.Test;

final class AdministratorDispositionReviewRequestTest {
    @Test
    void createsOnlyConfirmedAdministratorReviewedExactHashObservation() {
        AdministratorDispositionReviewRequest request = new AdministratorDispositionReviewRequest(
                "CASE-42", ArtifactType.MOD, "example.mod", "1.0.0", "AA".repeat(32));

        assertEquals("aa".repeat(32), request.sha256());
        assertEquals(ObservationOrigin.ADMIN_REVIEWED, request.observation().origin());
        assertEquals(Confidence.CONFIRMED, request.observation().confidence());
        assertEquals(ArtifactType.RESOURCE_PACK,
                AdministratorDispositionReviewRequest.parseArtifactType("resource-pack"));
    }

    @Test
    void rejectsWhitespaceUnsupportedTypesAndMalformedHashes() {
        assertThrows(IllegalArgumentException.class, () -> new AdministratorDispositionReviewRequest(
                "CASE 42", ArtifactType.MOD, "example.mod", "1", "00".repeat(32)));
        assertThrows(IllegalArgumentException.class, () -> new AdministratorDispositionReviewRequest(
                "CASE-42", ArtifactType.BEHAVIOR, "speed", "1", "00".repeat(32)));
        assertThrows(IllegalArgumentException.class, () -> new AdministratorDispositionReviewRequest(
                "CASE-42", ArtifactType.MOD, "example.mod", "1", "not-a-hash"));
    }
}