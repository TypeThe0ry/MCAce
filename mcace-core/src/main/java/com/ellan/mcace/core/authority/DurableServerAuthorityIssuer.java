package com.ellan.mcace.core.authority;

import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.Signature;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Public durable-journal primitive for an exact verified authority grant.
 *
 * <p>It validates the exact grant and expected durable sequence, signs, appends the content-free
 * record, forces that append, and only then creates a capability. The raw frame remains
 * package-private until a future committed transport facade is implemented.</p>
 */
public final class DurableServerAuthorityIssuer implements AutoCloseable {
    private final ServerAuthorityObservationCodec codec;
    private final KeyPair backendKeyPair;
    private final String backendKeyIdSha256;
    private final ServerAuthorityIssuanceJournal journal;
    private final FileServerAuthorityIssuanceJournal ownedJournal;
    private boolean poisoned;
    private boolean closed;

    public DurableServerAuthorityIssuer(
            ServerAuthorityObservationCodec codec,
            KeyPair backendKeyPair,
            Path preprovisionedJournal,
            long journalQuotaBytes) throws IOException {
        this.codec = Objects.requireNonNull(codec, "codec");
        this.backendKeyPair = requireMatchingEd25519KeyPair(backendKeyPair);
        this.backendKeyIdSha256 = BackendAuthorityPin.keyIdFor(this.backendKeyPair.getPublic());
        FileServerAuthorityIssuanceJournal opened =
                new FileServerAuthorityIssuanceJournal(
                        Objects.requireNonNull(preprovisionedJournal, "preprovisionedJournal"),
                        journalQuotaBytes);
        this.journal = opened;
        this.ownedJournal = opened;
    }

    DurableServerAuthorityIssuer(
            ServerAuthorityObservationCodec codec,
            KeyPair backendKeyPair,
            ServerAuthorityIssuanceJournal journal) {
        this.codec = Objects.requireNonNull(codec, "codec");
        this.backendKeyPair = requireMatchingEd25519KeyPair(backendKeyPair);
        this.backendKeyIdSha256 = BackendAuthorityPin.keyIdFor(this.backendKeyPair.getPublic());
        this.journal = Objects.requireNonNull(journal, "journal");
        this.ownedJournal = null;
    }

    public synchronized DurablyIssuedServerAuthorityObservation issue(
            BackendAuthorityGrantCodec.VerifiedGrant grant,
            long expectedObservationSequence,
            ServerAuthorityObservationCodec.ObservationRequest request)
            throws AuthorityProtocolException, IOException {
        Objects.requireNonNull(grant, "grant");
        Objects.requireNonNull(request, "request");
        if (expectedObservationSequence <= 0L) {
            throw new AuthorityProtocolException("expected authority observation sequence is invalid");
        }
        if (!backendKeyIdSha256.equals(request.backendKeyIdSha256())
                || expectedObservationSequence != request.observationSequence()
                || !requestMatchesGrant(grant, request)) {
            throw new AuthorityProtocolException(
                    "authority request does not match the configured issuer and verified grant");
        }
        ensureHealthy();
        String lifecycleCommitment = AuthorityIssuanceCommitments.lifecycle(grant);
        long observationSequence;
        try {
            observationSequence = Math.incrementExact(
                    recoverLastSequence(lifecycleCommitment));
        } catch (ArithmeticException exception) {
            throw new AuthorityProtocolException(
                    "authority observation sequence is exhausted", exception);
        }
        if (observationSequence != expectedObservationSequence) {
            throw new AuthoritySequenceMismatchException();
        }
        ServerAuthorityObservationCodec.IssuedObservation signed =
                codec.sign(request, backendKeyPair.getPrivate());
        if (signed.issuedAt().isBefore(grant.issuedAt())
                || !signed.issuedAt().isBefore(grant.expiresAt())
                || signed.expiresAt().isAfter(grant.expiresAt())) {
            throw new AuthorityProtocolException(
                    "authority observation lifetime is outside the verified grant window");
        }
        byte[] frame = signed.frame();
        String frameSha256 = AuthorityProtocolSupport.sha256(frame);
        ServerAuthorityIssuanceRecord record = new ServerAuthorityIssuanceRecord(
                signed.attestationId(), request.backendKeyIdSha256(),
                observationSequence, lifecycleCommitment,
                AuthorityIssuanceCommitments.providers(request), request.observedAt(),
                signed.issuedAt(), signed.expiresAt(), frameSha256);
        try {
            journal.appendAndForce(record);
            return new DurablyIssuedServerAuthorityObservation(
                    frame, signed.attestationId(), observationSequence, signed.issuedAt(),
                    signed.expiresAt(), frameSha256, request.grantId(),
                    request.grantCommitmentSha256(), lifecycleCommitment,
                    backendKeyIdSha256);
        } catch (IOException exception) {
            throw poison(exception);
        } catch (RuntimeException exception) {
            // A runtime failure after append may have an uncertain durable outcome. The same
            // issuer instance must never allocate or expose another frame after that boundary.
            poisoned = true;
            throw exception;
        }
    }

    private static boolean requestMatchesGrant(
            BackendAuthorityGrantCodec.VerifiedGrant grant,
            ServerAuthorityObservationCodec.ObservationRequest request) {
        return grant.backendInstanceId().equals(request.backendInstanceId())
                && grant.playerId().equals(request.playerId())
                && grant.authenticatedSessionId().equals(request.authenticatedSessionId())
                && grant.grantId().equals(request.grantId())
                && grant.commitmentSha256().equals(request.grantCommitmentSha256())
                && java.security.MessageDigest.isEqual(
                grant.physicalLoginBinding(), request.physicalLoginBinding())
                && grant.admissionTransportSequence() == request.admissionTransportSequence()
                && !request.observedAt().isBefore(grant.issuedAt())
                && request.observedAt().isBefore(grant.expiresAt())
                && request.providers().stream().allMatch(provider ->
                !provider.windowStartedAt().isBefore(grant.issuedAt()))
                && AuthorityIssuanceCommitments.lifecycle(grant).equals(
                AuthorityIssuanceCommitments.lifecycle(request));
    }

    /** Recovers the durable sequence for an exact verified grant without provider input. */
    public synchronized RecoveredServerAuthoritySequence recover(
            BackendAuthorityGrantCodec.VerifiedGrant grant) throws IOException {
        Objects.requireNonNull(grant, "grant");
        ensureHealthy();
        String lifecycleCommitment = AuthorityIssuanceCommitments.lifecycle(grant);
        return new RecoveredServerAuthoritySequence(
                grant, lifecycleCommitment, backendKeyIdSha256,
                recoverLastSequence(lifecycleCommitment));
    }

    @Override
    public synchronized void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        if (ownedJournal != null) {
            ownedJournal.close();
        }
    }

    private void ensureHealthy() throws IOException {
        if (closed) {
            throw new IOException("backend authority issuer is closed");
        }
        if (poisoned) {
            throw new IOException("backend authority issuer is poisoned");
        }
    }

    private IOException poison(IOException exception) {
        poisoned = true;
        return exception;
    }

    private long recoverLastSequence(String lifecycleCommitment) throws IOException {
        try {
            long recovered = journal.lastSequence(lifecycleCommitment);
            if (recovered < 0L) {
                throw new IOException("authority issuance journal returned a negative sequence");
            }
            return recovered;
        } catch (IOException exception) {
            throw poison(exception);
        }
    }

    private static KeyPair requireMatchingEd25519KeyPair(KeyPair keyPair) {
        Objects.requireNonNull(keyPair, "backendKeyPair");
        if (keyPair.getPrivate() == null || keyPair.getPublic() == null) {
            throw new IllegalArgumentException("backend authority key pair is incomplete");
        }
        try {
            byte[] challenge = "mcace/server-authority/key-pair-check/v1"
                    .getBytes(StandardCharsets.US_ASCII);
            Signature signer = Signature.getInstance("Ed25519");
            signer.initSign(keyPair.getPrivate());
            signer.update(challenge);
            byte[] signature = signer.sign();
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(keyPair.getPublic());
            verifier.update(challenge);
            if (!verifier.verify(signature)) {
                throw new IllegalArgumentException("backend authority key pair does not match");
            }
            // Canonicalize and validate the public half through the same pin primitive as proxies.
            BackendAuthorityPin.keyIdFor(keyPair.getPublic());
            return keyPair;
        } catch (GeneralSecurityException | RuntimeException exception) {
            if (exception instanceof IllegalArgumentException illegalArgumentException) {
                throw illegalArgumentException;
            }
            throw new IllegalArgumentException("invalid Ed25519 backend authority key pair", exception);
        }
    }
}
