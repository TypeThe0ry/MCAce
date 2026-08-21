package com.ellan.mcace.core.authority;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ellan.mcace.protocol.generated.BackendAuthorityGrant;
import com.ellan.mcace.protocol.generated.ServerAuthorityObservation;
import com.ellan.mcace.protocol.generated.ServerAuthorityProviderSummary;
import com.google.protobuf.Descriptors.Descriptor;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.Locale;
import java.util.Set;
import org.junit.jupiter.api.Test;

final class VerifiedServerAuthorityObservationTest {
    private static final Set<String> FORBIDDEN_AUTHORITY_TERMS = Set.of(
            "origin", "confidence", "action", "rule", "route", "kick", "ban");

    @Test
    void verifiedAuthorityTokensCannotBeConstructedByExternalPackages() {
        assertTrue(Modifier.isFinal(VerifiedServerAuthorityObservation.class.getModifiers()));
        assertTrue(Modifier.isFinal(
                BackendAuthorityGrantCodec.VerifiedGrant.class.getModifiers()));
        assertTrue(Arrays.stream(VerifiedServerAuthorityObservation.class.getDeclaredConstructors())
                .noneMatch(constructor -> Modifier.isPublic(constructor.getModifiers())));
        assertTrue(Arrays.stream(
                        BackendAuthorityGrantCodec.VerifiedGrant.class.getDeclaredConstructors())
                .noneMatch(constructor -> Modifier.isPublic(constructor.getModifiers())));
    }

    @Test
    void verifiedObservationExposesNoDispositionOrSelfAssertedAuthorityComponents() {
        Arrays.stream(VerifiedServerAuthorityObservation.class.getDeclaredFields())
                .map(field -> field.getName().toLowerCase(Locale.ROOT))
                .forEach(name -> FORBIDDEN_AUTHORITY_TERMS.forEach(term ->
                        assertFalse(name.contains(term), name + " exposes forbidden term " + term)));
        Arrays.stream(VerifiedServerAuthorityObservation.class.getDeclaredMethods())
                .filter(method -> Modifier.isPublic(method.getModifiers()))
                .map(method -> method.getName().toLowerCase(Locale.ROOT))
                .forEach(name -> FORBIDDEN_AUTHORITY_TERMS.forEach(term ->
                        assertFalse(name.contains(term), name + " exposes forbidden term " + term)));
    }

    @Test
    void wireMessagesContainNoDispositionOrSelfAssertedAuthorityFields() {
        assertDescriptorHasNoForbiddenFields(BackendAuthorityGrant.getDescriptor());
        assertDescriptorHasNoForbiddenFields(ServerAuthorityProviderSummary.getDescriptor());
        assertDescriptorHasNoForbiddenFields(ServerAuthorityObservation.getDescriptor());
    }

    private static void assertDescriptorHasNoForbiddenFields(Descriptor descriptor) {
        descriptor.getFields().forEach(field -> FORBIDDEN_AUTHORITY_TERMS.forEach(term ->
                assertFalse(field.getName().toLowerCase(Locale.ROOT).contains(term),
                        descriptor.getFullName() + "." + field.getName()
                                + " exposes forbidden term " + term)));
    }
}
