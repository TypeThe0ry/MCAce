package com.ellan.mcace.core.authority;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/** Domain-separated, content-free commitments retained by the issuance journal. */
final class AuthorityIssuanceCommitments {
    private AuthorityIssuanceCommitments() {
    }

    static String lifecycle(ServerAuthorityObservationCodec.ObservationRequest request) {
        return lifecycle(request.backendInstanceId(), request.playerId(),
                request.authenticatedSessionId(), request.physicalLoginBinding());
    }

    static String lifecycle(BackendAuthorityGrantCodec.VerifiedGrant grant) {
        return lifecycle(grant.backendInstanceId(), grant.playerId(),
                grant.authenticatedSessionId(), grant.physicalLoginBinding());
    }

    private static String lifecycle(
            String backendInstanceId,
            java.util.UUID playerId,
            String authenticatedSessionId,
            byte[] physicalLoginBinding) {
        return digest("mcace/server-authority/issuance-lifecycle/v1", output -> {
            text(output, backendInstanceId);
            text(output, playerId.toString());
            text(output, authenticatedSessionId);
            bytes(output, physicalLoginBinding);
        });
    }

    static String providers(ServerAuthorityObservationCodec.ObservationRequest request) {
        List<ProviderEvidence> providers = request.providers().stream()
                .map(provider -> new ProviderEvidence(
                        provider.trustDomainId(), provider.providerId(),
                        provider.providerVersion(), provider.stableCheckFamily(),
                        provider.threshold(), provider.observedCount(),
                        provider.windowStartedAt().toEpochMilli(),
                        provider.windowEndedAt().toEpochMilli()))
                .toList();
        return providers(request.authorityProfileSha256(), providers);
    }

    static String providers(VerifiedServerAuthorityObservation observation) {
        List<ProviderEvidence> providers = observation.providers().stream()
                .map(provider -> new ProviderEvidence(
                        provider.trustDomainId(), provider.providerId(),
                        provider.providerVersion(), provider.stableCheckFamily(),
                        provider.threshold(), provider.observedCount(),
                        provider.windowStartedAt().toEpochMilli(),
                        provider.windowEndedAt().toEpochMilli()))
                .toList();
        return providers(observation.authorityProfileSha256(), providers);
    }

    private static String providers(String authorityProfileSha256,
            List<ProviderEvidence> providers) {
        return digest("mcace/server-authority/provider-profile/v1", output -> {
            text(output, authorityProfileSha256);
            List<ProviderEvidence> ordered = new ArrayList<>(providers);
            ordered.sort(Comparator
                    .comparing(ProviderEvidence::providerId)
                    .thenComparing(ProviderEvidence::trustDomainId));
            output.writeInt(ordered.size());
            for (ProviderEvidence provider : ordered) {
                text(output, provider.trustDomainId());
                text(output, provider.providerId());
                text(output, provider.providerVersion());
                text(output, provider.stableCheckFamily());
                output.writeInt(provider.threshold());
                output.writeInt(provider.observedCount());
                output.writeLong(provider.windowStartedAtEpochMs());
                output.writeLong(provider.windowEndedAtEpochMs());
            }
        });
    }

    private static String digest(String domain, Writer writer) {
        try {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            try (DataOutputStream output = new DataOutputStream(bytes)) {
                text(output, domain);
                writer.write(output);
            }
            return java.util.HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(bytes.toByteArray()));
        } catch (IOException exception) {
            throw new IllegalStateException("in-memory authority commitment failed", exception);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("JDK SHA-256 is unavailable", exception);
        }
    }

    private static void text(DataOutputStream output, String value) throws IOException {
        bytes(output, value.getBytes(StandardCharsets.UTF_8));
    }

    private static void bytes(DataOutputStream output, byte[] value) throws IOException {
        output.writeInt(value.length);
        output.write(value);
    }

    @FunctionalInterface
    private interface Writer {
        void write(DataOutputStream output) throws IOException;
    }

    private record ProviderEvidence(
            String trustDomainId,
            String providerId,
            String providerVersion,
            String stableCheckFamily,
            int threshold,
            int observedCount,
            long windowStartedAtEpochMs,
            long windowEndedAtEpochMs) {
    }
}
