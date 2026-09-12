package com.ellan.mcace.protocol.federation;

import com.ellan.mcace.protocol.ProtocolConstants;
import com.ellan.mcace.protocol.crypto.NonceReplayGuard;
import com.ellan.mcace.protocol.generated.ClientFederationConsent;
import com.ellan.mcace.protocol.generated.FederationAssertion;
import com.ellan.mcace.protocol.generated.FederationConsentRequest;
import com.ellan.mcace.protocol.generated.FederationGrant;
import com.ellan.mcace.protocol.generated.FederationLocalClaim;
import com.ellan.mcace.protocol.generated.FederationPresentation;
import com.ellan.mcace.protocol.generated.FederationPresentationProof;
import com.ellan.mcace.protocol.generated.SignedFederationAssertion;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/** Stateless federation document creation and verification. This class performs no I/O. */
public final class FederationDocuments {
    public static final String MINIMAL_DISCLOSURE = "source_locally_verified";

    private static final byte[] CLIENT_SIGNATURE_DOMAIN =
            "mcace-federation-client-consent-v1\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] SOURCE_SIGNATURE_DOMAIN =
            "mcace-federation-source-assertion-v1\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] PRESENTATION_PROOF_SIGNATURE_DOMAIN =
            "mcace-federation-presentation-proof-v1\0".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] REPLAY_TOKEN_DOMAIN =
            "mcace-federation-replay-v1\0".getBytes(StandardCharsets.US_ASCII);
    private static final int SHA256_BYTES = 32;
    private static final int ED25519_SIGNATURE_BYTES = 64;
    private static final int MAX_CLIENT_PUBLIC_KEY_X509_BYTES = 128;
    private static final int MAX_INNER_DOCUMENT_BYTES = 4 * 1024;

    private FederationDocuments() {
    }

    public static FederationConsentRequest issueConsentRequest(
            String sourceNetworkId,
            String targetNetworkId,
            String playerUuid,
            PublicKey clientSessionPublicKey,
            PublicKey sourceSigningPublicKey,
            PublicKey targetIdentityPublicKey,
            String localAuthenticatedSessionId,
            String policyVersion,
            byte[] policySha256,
            Clock clock,
            Duration lifetime,
            SecureRandom random) throws FederationException {
        Objects.requireNonNull(clock, "clock");
        Objects.requireNonNull(random, "random");
        long lifetimeMillis = validLifetime(lifetime);
        long issuedAt = clock.millis();
        long expiresAt = safeAdd(issuedAt, lifetimeMillis, "federation expiry overflow");
        byte[] nonce = new byte[ProtocolConstants.NONCE_BYTES];
        random.nextBytes(nonce);
        FederationConsentRequest request = FederationConsentRequest.newBuilder()
                .setSchemaVersion(ProtocolConstants.FEDERATION_SCHEMA_VERSION)
                .setSourceNetworkId(Objects.requireNonNull(sourceNetworkId, "sourceNetworkId"))
                .setTargetNetworkId(Objects.requireNonNull(targetNetworkId, "targetNetworkId"))
                .setPlayerUuid(Objects.requireNonNull(playerUuid, "playerUuid"))
                .setClientPublicKeySha256(ByteString.copyFrom(keyId(clientSessionPublicKey)))
                .setLocalAuthenticatedSessionId(Objects.requireNonNull(
                        localAuthenticatedSessionId, "localAuthenticatedSessionId"))
                .setAssertionId(UUID.randomUUID().toString())
                .setAssertionNonce(ByteString.copyFrom(nonce))
                .setIssuedAtEpochMs(issuedAt)
                .setExpiresAtEpochMs(expiresAt)
                .setPolicyVersion(Objects.requireNonNull(policyVersion, "policyVersion"))
                .setPolicySha256(ByteString.copyFrom(Objects.requireNonNull(policySha256, "policySha256")))
                .setDisclosure(MINIMAL_DISCLOSURE)
                .setSourceKeyIdSha256(ByteString.copyFrom(keyId(sourceSigningPublicKey)))
                .setTargetKeyIdSha256(ByteString.copyFrom(keyId(targetIdentityPublicKey)))
                .build();
        validateRequest(request);
        return request;
    }

    public static ClientFederationConsent signClientConsent(
            FederationConsentRequest request,
            PrivateKey clientPrivateKey,
            PublicKey clientPublicKey,
            Clock clock,
            Duration allowedClockSkew) throws FederationException {
        validateRequestAtTime(request, clock, allowedClockSkew);
        if (!MessageDigest.isEqual(keyId(clientPublicKey), request.getClientPublicKeySha256().toByteArray())) {
            throw new FederationException("client key does not match consent request binding");
        }
        ClientFederationConsent unsigned = consentFrom(request).build();
        return unsigned.toBuilder()
                .setClientSignature(ByteString.copyFrom(sign(
                        signatureBytes(CLIENT_SIGNATURE_DOMAIN, unsigned.toByteArray()), clientPrivateKey)))
                .build();
    }

    public static FederationConsentRequest parseConsentRequest(
            byte[] encoded, Clock clock, Duration allowedClockSkew) throws FederationException {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length > MAX_INNER_DOCUMENT_BYTES) {
            throw new FederationException("federation consent request exceeds encoded budget");
        }
        FederationConsentRequest request;
        try {
            request = FederationConsentRequest.parseFrom(encoded);
        } catch (InvalidProtocolBufferException exception) {
            throw new FederationException("malformed federation consent request", exception);
        }
        validateRequestAtTime(request, clock, allowedClockSkew);
        return request;
    }

    public static void validateConsentRequestBindings(
            FederationConsentRequest request,
            String expectedSourceNetworkId,
            String expectedTargetNetworkId,
            String expectedPlayerUuid,
            PublicKey expectedClientSessionPublicKey,
            PublicKey expectedSourceIdentityPublicKey,
            PublicKey expectedTargetIdentityPublicKey,
            String expectedLocalAuthenticatedSessionId) throws FederationException {
        validateRequest(request);
        if (!request.getSourceNetworkId().equals(expectedSourceNetworkId)
                || !request.getTargetNetworkId().equals(expectedTargetNetworkId)
                || !request.getPlayerUuid().equals(expectedPlayerUuid)
                || !request.getLocalAuthenticatedSessionId().equals(expectedLocalAuthenticatedSessionId)
                || !MessageDigest.isEqual(request.getClientPublicKeySha256().toByteArray(),
                        keyId(expectedClientSessionPublicKey))
                || !MessageDigest.isEqual(request.getSourceKeyIdSha256().toByteArray(),
                        keyId(expectedSourceIdentityPublicKey))
                || !MessageDigest.isEqual(request.getTargetKeyIdSha256().toByteArray(),
                        keyId(expectedTargetIdentityPublicKey))) {
            throw new FederationException("federation consent request binding mismatch");
        }
    }

    public static ClientFederationConsent parseConsentResponse(byte[] encoded) throws FederationException {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length > MAX_INNER_DOCUMENT_BYTES) {
            throw new FederationException("client federation consent exceeds encoded budget");
        }
        ClientFederationConsent consent;
        try {
            consent = ClientFederationConsent.parseFrom(encoded);
        } catch (InvalidProtocolBufferException exception) {
            throw new FederationException("malformed client federation consent", exception);
        }
        validateConsent(consent);
        return consent;
    }

    public static byte[] encodeConsentResponse(ClientFederationConsent consent) throws FederationException {
        validateConsent(consent);
        return consent.toByteArray();
    }

    public static SignedFederationAssertion signAssertion(
            FederationConsentRequest request,
            ClientFederationConsent consent,
            PublicKey clientPublicKey,
            PrivateKey sourcePrivateKey,
            PublicKey sourcePublicKey,
            Clock clock,
            Duration allowedClockSkew) throws FederationException {
        validateRequestAtTime(request, clock, allowedClockSkew);
        validateConsent(consent);
        requireSameBindings(request, consent);
        verifyClientSignature(consent, clientPublicKey);
        long sourceAuthorizedAt = Objects.requireNonNull(clock, "clock").millis();
        validateAtTime(request.getIssuedAtEpochMs(), request.getExpiresAtEpochMs(),
                sourceAuthorizedAt, validClockSkew(allowedClockSkew));
        FederationAssertion assertion = assertionFrom(request, consent)
                .setSourceAuthorizedAtEpochMs(sourceAuthorizedAt)
                .build();
        validateAssertion(assertion);
        if (!MessageDigest.isEqual(keyId(sourcePublicKey), assertion.getSourceKeyIdSha256().toByteArray())) {
            throw new FederationException("source signing key does not match consented source key");
        }
        byte[] assertionBytes = assertion.toByteArray();
        return SignedFederationAssertion.newBuilder()
                .setAssertion(ByteString.copyFrom(assertionBytes))
                .setSourceKeyIdSha256(ByteString.copyFrom(keyId(sourcePublicKey)))
                .setSignature(ByteString.copyFrom(sign(
                        signatureBytes(SOURCE_SIGNATURE_DOMAIN, assertionBytes), sourcePrivateKey)))
                .build();
    }

    public static FederationGrant grant(
            ClientFederationConsent consent,
            SignedFederationAssertion assertion,
            PublicKey clientSessionPublicKey) throws FederationException {
        Objects.requireNonNull(consent, "consent");
        Objects.requireNonNull(assertion, "assertion");
        Objects.requireNonNull(clientSessionPublicKey, "clientSessionPublicKey");
        FederationGrant grant = FederationGrant.newBuilder()
                .setSchemaVersion(ProtocolConstants.FEDERATION_SCHEMA_VERSION)
                .setClientConsent(consent)
                .setSignedAssertion(assertion)
                .setClientPublicKeyX509(ByteString.copyFrom(clientSessionPublicKey.getEncoded()))
                .build();
        validateGrant(grant);
        return grant;
    }

    public static byte[] encodeGrant(FederationGrant grant) throws FederationException {
        validateGrant(grant);
        return grant.toByteArray();
    }

    /**
     * Exact federation target-authentication binding. The digest covers the complete protobuf
     * encoding of {@link SignedFederationAssertion}, including the canonical assertion bytes,
     * source key id, and source signature. It is the same value carried by presentation proof.
     */
    public static byte[] signedAssertionSha256(FederationGrant grant) throws FederationException {
        validateGrant(grant);
        return sha256(grant.getSignedAssertion().toByteArray());
    }

    public static FederationGrant verifyGrant(
            byte[] encoded,
            FederationConsentRequest expectedRequest,
            PublicKey clientSessionPublicKey,
            PublicKey pinnedSourcePublicKey,
            Clock clock,
            Duration allowedClockSkew) throws FederationException {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length > MAX_INNER_DOCUMENT_BYTES) {
            throw new FederationException("federation grant exceeds encoded budget");
        }
        FederationGrant grant;
        try {
            grant = FederationGrant.parseFrom(encoded);
        } catch (InvalidProtocolBufferException exception) {
            throw new FederationException("malformed federation grant", exception);
        }
        validateGrant(grant);
        Objects.requireNonNull(clock, "clock");
        long verificationTime = clock.millis();
        long skewMillis = validClockSkew(allowedClockSkew);
        validateRequest(expectedRequest);
        validateAtTime(expectedRequest.getIssuedAtEpochMs(), expectedRequest.getExpiresAtEpochMs(),
                verificationTime, skewMillis);
        if (!MessageDigest.isEqual(keyId(clientSessionPublicKey),
                grant.getClientConsent().getClientPublicKeySha256().toByteArray())
                || !Arrays.equals(clientSessionPublicKey.getEncoded(), grant.getClientPublicKeyX509().toByteArray())) {
            throw new FederationException("federation grant client session key mismatch");
        }
        verifyClientSignature(grant.getClientConsent(), clientSessionPublicKey);
        requireSameBindings(expectedRequest, grant.getClientConsent());
        SignedFederationAssertion signed = grant.getSignedAssertion();
        byte[] sourceKeyId = keyId(pinnedSourcePublicKey);
        if (!MessageDigest.isEqual(sourceKeyId, signed.getSourceKeyIdSha256().toByteArray())
                || !verifySignature(signatureBytes(SOURCE_SIGNATURE_DOMAIN, signed.getAssertion().toByteArray()),
                        signed.getSignature().toByteArray(), pinnedSourcePublicKey)) {
            throw new FederationException("invalid or unpinned federation grant signature");
        }
        FederationAssertion assertion;
        try {
            assertion = FederationAssertion.parseFrom(signed.getAssertion());
        } catch (InvalidProtocolBufferException exception) {
            throw new FederationException("malformed federation assertion", exception);
        }
        validateAssertion(assertion);
        requireSameBindings(assertion, grant.getClientConsent());
        if (!MessageDigest.isEqual(sourceKeyId, assertion.getSourceKeyIdSha256().toByteArray())
                || !MessageDigest.isEqual(sha256(grant.getClientConsent().toByteArray()),
                        assertion.getClientConsentSha256().toByteArray())) {
            throw new FederationException("federation grant signed bindings mismatch");
        }
        validateAtTime(assertion.getSourceAuthorizedAtEpochMs(), assertion.getExpiresAtEpochMs(),
                verificationTime, skewMillis);
        return grant;
    }

    public static FederationPresentation presentation(
            FederationGrant grant,
            PrivateKey clientSessionPrivateKey,
            String targetAuthenticatedSessionId,
            byte[] targetChallengeNonce,
            Clock clock) throws FederationException {
        validateGrant(grant);
        Objects.requireNonNull(clock, "clock");
        ClientFederationConsent consent = grant.getClientConsent();
        SignedFederationAssertion assertion = grant.getSignedAssertion();
        FederationAssertion assertionBody;
        try {
            assertionBody = FederationAssertion.parseFrom(assertion.getAssertion());
        } catch (InvalidProtocolBufferException exception) {
            throw new FederationException("malformed federation assertion", exception);
        }
        validateAssertion(assertionBody);
        requireSameBindings(assertionBody, consent);
        requireText(targetAuthenticatedSessionId, ProtocolConstants.MAX_FEDERATION_ID_CHARS,
                "target authenticated session id");
        if (targetChallengeNonce == null || targetChallengeNonce.length != ProtocolConstants.NONCE_BYTES) {
            throw new FederationException("invalid target federation challenge length");
        }
        FederationPresentationProof unsignedProof = FederationPresentationProof.newBuilder()
                .setSchemaVersion(ProtocolConstants.FEDERATION_SCHEMA_VERSION)
                .setSignedAssertionSha256(ByteString.copyFrom(sha256(assertion.toByteArray())))
                .setAssertionId(assertionBody.getAssertionId())
                .setTargetNetworkId(assertionBody.getTargetNetworkId())
                .setTargetAuthenticatedSessionId(targetAuthenticatedSessionId)
                .setTargetChallengeNonce(ByteString.copyFrom(targetChallengeNonce))
                .setPresentedAtEpochMs(clock.millis())
                .setTargetPlayerUuid(assertionBody.getPlayerUuid())
                .build();
        FederationPresentationProof proof = unsignedProof.toBuilder()
                .setClientSignature(ByteString.copyFrom(sign(signatureBytes(
                        PRESENTATION_PROOF_SIGNATURE_DOMAIN, unsignedProof.toByteArray()), clientSessionPrivateKey)))
                .build();
        FederationPresentation presentation = FederationPresentation.newBuilder()
                .setSchemaVersion(ProtocolConstants.FEDERATION_SCHEMA_VERSION)
                .setGrant(grant)
                .setPresentationProof(proof)
                .build();
        validatePresentationStructure(presentation);
        return presentation;
    }

    public static byte[] encode(FederationPresentation presentation) throws FederationException {
        validatePresentationStructure(presentation);
        byte[] encoded = presentation.toByteArray();
        if (encoded.length > ProtocolConstants.MAX_FEDERATION_PRESENTATION_BYTES) {
            throw new FederationException("federation presentation exceeds encoded budget");
        }
        return encoded;
    }

    /**
     * Verifies a target presentation. expectedClientPublicKeySha256 is the key hash of
     * the target's already-authenticated client session; phase one therefore requires
     * the client to reuse the same short-lived source session key while presenting.
     */
    public static FederationVerification verify(
            byte[] encoded,
            PublicKey pinnedSourcePublicKey,
            PublicKey targetIdentityPublicKey,
            byte[] expectedClientPublicKeySha256,
            String expectedSourceNetworkId,
            String expectedTargetNetworkId,
            String expectedPlayerUuid,
            String expectedTargetAuthenticatedSessionId,
            byte[] expectedTargetChallengeNonce,
            byte[] expectedFederationSignedAssertionSha256,
            Clock clock,
            Duration allowedClockSkew,
            NonceReplayGuard replayGuard) throws FederationException {
        Objects.requireNonNull(encoded, "encoded");
        if (encoded.length > ProtocolConstants.MAX_FEDERATION_PRESENTATION_BYTES) {
            throw new FederationException("federation presentation exceeds encoded budget");
        }
        FederationPresentation presentation;
        try {
            presentation = FederationPresentation.parseFrom(encoded);
        } catch (InvalidProtocolBufferException exception) {
            throw new FederationException("malformed federation presentation", exception);
        }
        validatePresentationStructure(presentation);
        Objects.requireNonNull(pinnedSourcePublicKey, "pinnedSourcePublicKey");
        Objects.requireNonNull(targetIdentityPublicKey, "targetIdentityPublicKey");
        requireSha256(expectedClientPublicKeySha256, "expected client public-key hash");
        requireNetworkId(expectedSourceNetworkId, "expected source network id");
        requireNetworkId(expectedTargetNetworkId, "expected target network id");
        requirePlayerUuid(expectedPlayerUuid);
        requireText(expectedTargetAuthenticatedSessionId, ProtocolConstants.MAX_FEDERATION_ID_CHARS,
                "expected target authenticated session id");
        if (expectedTargetChallengeNonce == null
                || expectedTargetChallengeNonce.length != ProtocolConstants.NONCE_BYTES) {
            throw new FederationException("invalid expected target federation challenge length");
        }
        requireSha256(expectedFederationSignedAssertionSha256,
                "expected target-auth signed assertion hash");
        Objects.requireNonNull(clock, "clock");
        long skewMillis = validClockSkew(allowedClockSkew);
        long verificationTime = clock.millis();
        Objects.requireNonNull(replayGuard, "replayGuard");

        FederationGrant grant = presentation.getGrant();
        PublicKey clientPublicKey = decodeClientPublicKey(grant.getClientPublicKeyX509().toByteArray());
        byte[] clientKeyId = keyId(clientPublicKey);
        if (!MessageDigest.isEqual(clientKeyId, expectedClientPublicKeySha256)) {
            throw new FederationException("presentation client key does not match authenticated target session");
        }

        ClientFederationConsent consent = grant.getClientConsent();
        validateConsent(consent);
        verifyClientSignature(consent, clientPublicKey);

        SignedFederationAssertion signed = grant.getSignedAssertion();
        validateSignedAssertion(signed);
        byte[] actualSignedAssertionSha256 = sha256(signed.toByteArray());
        if (!MessageDigest.isEqual(actualSignedAssertionSha256,
                expectedFederationSignedAssertionSha256)) {
            // This check deliberately precedes replayGuard.accept. A target AUTH transcript that
            // did not bind the exact source-signed grant must not burn the legitimate one-shot
            // presentation and deny the correctly bound retry.
            throw new FederationException("federation target-auth assertion binding mismatch");
        }
        byte[] pinnedKeyId = keyId(pinnedSourcePublicKey);
        if (!MessageDigest.isEqual(pinnedKeyId, signed.getSourceKeyIdSha256().toByteArray())) {
            throw new FederationException("federation source key is not pinned");
        }
        if (!verifySignature(signatureBytes(SOURCE_SIGNATURE_DOMAIN, signed.getAssertion().toByteArray()),
                signed.getSignature().toByteArray(), pinnedSourcePublicKey)) {
            throw new FederationException("invalid federation source signature");
        }
        FederationAssertion assertion;
        try {
            assertion = FederationAssertion.parseFrom(signed.getAssertion());
        } catch (InvalidProtocolBufferException exception) {
            throw new FederationException("malformed federation assertion", exception);
        }
        validateAssertion(assertion);
        if (!MessageDigest.isEqual(pinnedKeyId, assertion.getSourceKeyIdSha256().toByteArray())
                || !MessageDigest.isEqual(keyId(targetIdentityPublicKey),
                        assertion.getTargetKeyIdSha256().toByteArray())) {
            throw new FederationException("federation network key binding mismatch");
        }
        requireSameBindings(assertion, consent);
        if (!MessageDigest.isEqual(sha256(consent.toByteArray()), assertion.getClientConsentSha256().toByteArray())) {
            throw new FederationException("federation consent hash mismatch");
        }
        if (!MessageDigest.isEqual(clientKeyId, assertion.getClientPublicKeySha256().toByteArray())) {
            throw new FederationException("federation client key hash mismatch");
        }
        if (!assertion.getSourceNetworkId().equals(expectedSourceNetworkId)
                || !assertion.getTargetNetworkId().equals(expectedTargetNetworkId)) {
            throw new FederationException("federation audience mismatch");
        }
        if (!assertion.getPlayerUuid().equals(expectedPlayerUuid)) {
            throw new FederationException("federation player binding mismatch");
        }
        validateAtTime(assertion.getIssuedAtEpochMs(), assertion.getExpiresAtEpochMs(),
                verificationTime, skewMillis);
        validateAtTime(assertion.getSourceAuthorizedAtEpochMs(), assertion.getExpiresAtEpochMs(),
                verificationTime, skewMillis);
        verifyPresentationProof(presentation.getPresentationProof(), signed, assertion, clientPublicKey,
                expectedTargetNetworkId, expectedPlayerUuid, expectedTargetAuthenticatedSessionId,
                expectedTargetChallengeNonce, verificationTime, skewMillis);
        byte[] replayToken = replayToken(assertion);
        String replayScope = "federation:" + expectedSourceNetworkId + "->" + expectedTargetNetworkId
                + ":" + assertion.getAssertionId();
        if (!replayGuard.accept(replayScope, replayToken)) {
            throw new FederationException("replayed federation assertion");
        }
        return new FederationVerification(
                assertion.getSourceNetworkId(), assertion.getTargetNetworkId(), assertion.getPlayerUuid(),
                assertion.getClientPublicKeySha256().toByteArray(),
                assertion.getLocalAuthenticatedSessionId(), assertion.getAssertionId(),
                actualSignedAssertionSha256,
                assertion.getIssuedAtEpochMs(), assertion.getSourceAuthorizedAtEpochMs(),
                assertion.getExpiresAtEpochMs(), verificationTime, assertion.getPolicyVersion(),
                assertion.getPolicySha256().toByteArray(), assertion.getDisclosure(), assertion.getLocalClaim());
    }

    public static NonceReplayGuard newReplayGuard(Clock clock) {
        return newReplayGuard(clock, ProtocolConstants.DEFAULT_CLOCK_SKEW);
    }

    public static NonceReplayGuard newReplayGuard(Clock clock, Duration allowedClockSkew) {
        long skewMillis;
        try {
            skewMillis = validClockSkew(allowedClockSkew);
        } catch (FederationException exception) {
            throw new IllegalArgumentException(exception.getMessage(), exception);
        }
        Duration replayWindow = ProtocolConstants.MAX_FEDERATION_ASSERTION_TTL.plusMillis(skewMillis);
        return new NonceReplayGuard(clock, replayWindow,
                ProtocolConstants.MAX_FEDERATION_REPLAY_ENTRIES, 1);
    }

    private static ClientFederationConsent.Builder consentFrom(FederationConsentRequest request) {
        return ClientFederationConsent.newBuilder()
                .setSchemaVersion(request.getSchemaVersion())
                .setSourceNetworkId(request.getSourceNetworkId())
                .setTargetNetworkId(request.getTargetNetworkId())
                .setPlayerUuid(request.getPlayerUuid())
                .setClientPublicKeySha256(request.getClientPublicKeySha256())
                .setLocalAuthenticatedSessionId(request.getLocalAuthenticatedSessionId())
                .setAssertionId(request.getAssertionId())
                .setAssertionNonce(request.getAssertionNonce())
                .setIssuedAtEpochMs(request.getIssuedAtEpochMs())
                .setExpiresAtEpochMs(request.getExpiresAtEpochMs())
                .setPolicyVersion(request.getPolicyVersion())
                .setPolicySha256(request.getPolicySha256())
                .setDisclosure(request.getDisclosure())
                .setSourceKeyIdSha256(request.getSourceKeyIdSha256())
                .setTargetKeyIdSha256(request.getTargetKeyIdSha256());
    }

    private static FederationAssertion.Builder assertionFrom(
            FederationConsentRequest request, ClientFederationConsent consent) throws FederationException {
        return FederationAssertion.newBuilder()
                .setSchemaVersion(request.getSchemaVersion())
                .setSourceNetworkId(request.getSourceNetworkId())
                .setTargetNetworkId(request.getTargetNetworkId())
                .setPlayerUuid(request.getPlayerUuid())
                .setClientPublicKeySha256(request.getClientPublicKeySha256())
                .setLocalAuthenticatedSessionId(request.getLocalAuthenticatedSessionId())
                .setAssertionId(request.getAssertionId())
                .setAssertionNonce(request.getAssertionNonce())
                .setIssuedAtEpochMs(request.getIssuedAtEpochMs())
                .setExpiresAtEpochMs(request.getExpiresAtEpochMs())
                .setPolicyVersion(request.getPolicyVersion())
                .setPolicySha256(request.getPolicySha256())
                .setDisclosure(request.getDisclosure())
                .setLocalClaim(FederationLocalClaim.FEDERATION_SOURCE_LOCALLY_VERIFIED)
                .setClientConsentSha256(ByteString.copyFrom(sha256(consent.toByteArray())))
                .setSourceKeyIdSha256(request.getSourceKeyIdSha256())
                .setTargetKeyIdSha256(request.getTargetKeyIdSha256());
    }

    private static void validatePresentationStructure(FederationPresentation presentation)
            throws FederationException {
        Objects.requireNonNull(presentation, "presentation");
        requireNoUnknown(presentation, "federation presentation");
        requireVersion(presentation.getSchemaVersion());
        if (!presentation.hasGrant() || !presentation.hasPresentationProof()) {
            throw new FederationException("federation presentation fields are missing");
        }
        validateGrant(presentation.getGrant());
        if (presentation.getSerializedSize() > ProtocolConstants.MAX_FEDERATION_PRESENTATION_BYTES) {
            throw new FederationException("federation presentation exceeds encoded budget");
        }
    }

    private static void validateGrant(FederationGrant grant) throws FederationException {
        Objects.requireNonNull(grant, "grant");
        requireNoUnknown(grant, "federation grant");
        requireVersion(grant.getSchemaVersion());
        if (!grant.hasClientConsent() || !grant.hasSignedAssertion()) {
            throw new FederationException("federation grant fields are missing");
        }
        int keyBytes = grant.getClientPublicKeyX509().size();
        if (keyBytes == 0 || keyBytes > MAX_CLIENT_PUBLIC_KEY_X509_BYTES) {
            throw new FederationException("client public key exceeds federation budget");
        }
        validateConsent(grant.getClientConsent());
        validateSignedAssertion(grant.getSignedAssertion());
        PublicKey key = decodeClientPublicKey(grant.getClientPublicKeyX509().toByteArray());
        if (!MessageDigest.isEqual(keyId(key), grant.getClientConsent().getClientPublicKeySha256().toByteArray())) {
            throw new FederationException("federation grant client public-key hash mismatch");
        }
        FederationAssertion body;
        try {
            body = FederationAssertion.parseFrom(grant.getSignedAssertion().getAssertion());
        } catch (InvalidProtocolBufferException exception) {
            throw new FederationException("malformed federation assertion", exception);
        }
        validateAssertion(body);
        requireSameBindings(body, grant.getClientConsent());
        if (!MessageDigest.isEqual(grant.getSignedAssertion().getSourceKeyIdSha256().toByteArray(),
                        body.getSourceKeyIdSha256().toByteArray())
                || !MessageDigest.isEqual(sha256(grant.getClientConsent().toByteArray()),
                        body.getClientConsentSha256().toByteArray())) {
            throw new FederationException("federation grant consent hash mismatch");
        }
        requireInnerBudget(grant, "federation grant");
    }

    private static void verifyPresentationProof(
            FederationPresentationProof proof,
            SignedFederationAssertion signedAssertion,
            FederationAssertion assertion,
            PublicKey clientPublicKey,
            String expectedTargetNetworkId,
            String expectedPlayerUuid,
            String expectedTargetSessionId,
            byte[] expectedTargetChallenge,
            long now,
            long allowedClockSkew) throws FederationException {
        validatePresentationProof(proof);
        if (!MessageDigest.isEqual(proof.getSignedAssertionSha256().toByteArray(),
                sha256(signedAssertion.toByteArray()))
                || !proof.getAssertionId().equals(assertion.getAssertionId())) {
            throw new FederationException("presentation proof assertion binding mismatch");
        }
        if (!proof.getTargetNetworkId().equals(expectedTargetNetworkId)
                || !proof.getTargetPlayerUuid().equals(expectedPlayerUuid)
                || !proof.getTargetAuthenticatedSessionId().equals(expectedTargetSessionId)
                || !MessageDigest.isEqual(proof.getTargetChallengeNonce().toByteArray(), expectedTargetChallenge)) {
            throw new FederationException("presentation proof target binding mismatch");
        }
        long earliest;
        try {
            earliest = Math.subtractExact(now,
                    Math.addExact(ProtocolConstants.MAX_FEDERATION_PRESENTATION_PROOF_AGE.toMillis(),
                            allowedClockSkew));
        } catch (ArithmeticException exception) {
            throw new FederationException("presentation proof time comparison overflow", exception);
        }
        if (proof.getPresentedAtEpochMs() > safeAdd(now, allowedClockSkew,
                "presentation proof time comparison overflow")
                || proof.getPresentedAtEpochMs() < earliest) {
            throw new FederationException("presentation proof is outside its freshness window");
        }
        FederationPresentationProof unsigned = proof.toBuilder().clearClientSignature().build();
        if (!verifySignature(signatureBytes(PRESENTATION_PROOF_SIGNATURE_DOMAIN, unsigned.toByteArray()),
                proof.getClientSignature().toByteArray(), clientPublicKey)) {
            throw new FederationException("invalid federation presentation proof signature");
        }
    }

    private static void validatePresentationProof(FederationPresentationProof proof) throws FederationException {
        requireNoUnknown(proof, "federation presentation proof");
        requireVersion(proof.getSchemaVersion());
        requireSha256(proof.getSignedAssertionSha256().toByteArray(), "signed assertion hash");
        requireCanonicalUuid(proof.getAssertionId(), "presentation assertion id");
        requireNetworkId(proof.getTargetNetworkId(), "presentation target network id");
        requirePlayerUuid(proof.getTargetPlayerUuid());
        requireText(proof.getTargetAuthenticatedSessionId(), ProtocolConstants.MAX_FEDERATION_ID_CHARS,
                "presentation target authenticated session id");
        if (proof.getTargetChallengeNonce().size() != ProtocolConstants.NONCE_BYTES) {
            throw new FederationException("invalid presentation target challenge length");
        }
        if (proof.getPresentedAtEpochMs() <= 0L
                || proof.getClientSignature().size() != ED25519_SIGNATURE_BYTES) {
            throw new FederationException("invalid federation presentation proof fields");
        }
        requireInnerBudget(proof, "federation presentation proof");
    }

    private static byte[] replayToken(FederationAssertion assertion) throws FederationException {
        byte[] assertionId = assertion.getAssertionIdBytes().toByteArray();
        ByteBuffer buffer = ByteBuffer.allocate(REPLAY_TOKEN_DOMAIN.length
                + Integer.BYTES + assertionId.length + ProtocolConstants.NONCE_BYTES);
        buffer.put(REPLAY_TOKEN_DOMAIN)
                .putInt(assertionId.length).put(assertionId)
                .put(assertion.getAssertionNonce().toByteArray());
        return sha256(buffer.array());
    }

    private static void validateRequest(FederationConsentRequest request) throws FederationException {
        Objects.requireNonNull(request, "request");
        requireNoUnknown(request, "federation consent request");
        requireVersion(request.getSchemaVersion());
        validateBindings(request.getSourceNetworkId(), request.getTargetNetworkId(), request.getPlayerUuid(),
                request.getClientPublicKeySha256().toByteArray(), request.getLocalAuthenticatedSessionId(),
                request.getAssertionId(), request.getAssertionNonce().toByteArray(), request.getIssuedAtEpochMs(),
                request.getExpiresAtEpochMs(), request.getPolicyVersion(), request.getPolicySha256().toByteArray(),
                request.getDisclosure(), request.getSourceKeyIdSha256().toByteArray(),
                request.getTargetKeyIdSha256().toByteArray());
        requireInnerBudget(request, "federation consent request");
    }

    private static void validateConsent(ClientFederationConsent consent) throws FederationException {
        Objects.requireNonNull(consent, "consent");
        requireNoUnknown(consent, "client federation consent");
        requireVersion(consent.getSchemaVersion());
        validateBindings(consent.getSourceNetworkId(), consent.getTargetNetworkId(), consent.getPlayerUuid(),
                consent.getClientPublicKeySha256().toByteArray(), consent.getLocalAuthenticatedSessionId(),
                consent.getAssertionId(), consent.getAssertionNonce().toByteArray(), consent.getIssuedAtEpochMs(),
                consent.getExpiresAtEpochMs(), consent.getPolicyVersion(), consent.getPolicySha256().toByteArray(),
                consent.getDisclosure(), consent.getSourceKeyIdSha256().toByteArray(),
                consent.getTargetKeyIdSha256().toByteArray());
        if (consent.getClientSignature().size() != ED25519_SIGNATURE_BYTES) {
            throw new FederationException("invalid client consent signature length");
        }
        requireInnerBudget(consent, "client federation consent");
    }

    private static void validateAssertion(FederationAssertion assertion) throws FederationException {
        Objects.requireNonNull(assertion, "assertion");
        requireNoUnknown(assertion, "federation assertion");
        requireVersion(assertion.getSchemaVersion());
        validateBindings(assertion.getSourceNetworkId(), assertion.getTargetNetworkId(), assertion.getPlayerUuid(),
                assertion.getClientPublicKeySha256().toByteArray(), assertion.getLocalAuthenticatedSessionId(),
                assertion.getAssertionId(), assertion.getAssertionNonce().toByteArray(),
                assertion.getIssuedAtEpochMs(), assertion.getExpiresAtEpochMs(), assertion.getPolicyVersion(),
                assertion.getPolicySha256().toByteArray(), assertion.getDisclosure(),
                assertion.getSourceKeyIdSha256().toByteArray(), assertion.getTargetKeyIdSha256().toByteArray());
        if (assertion.getLocalClaim() != FederationLocalClaim.FEDERATION_SOURCE_LOCALLY_VERIFIED) {
            throw new FederationException("unsupported federation local claim");
        }
        if (assertion.getSourceAuthorizedAtEpochMs() < assertion.getIssuedAtEpochMs()
                || assertion.getSourceAuthorizedAtEpochMs() >= assertion.getExpiresAtEpochMs()) {
            throw new FederationException("invalid federation source authorization time");
        }
        requireSha256(assertion.getClientConsentSha256().toByteArray(), "client consent hash");
        requireInnerBudget(assertion, "federation assertion");
    }

    private static void validateSignedAssertion(SignedFederationAssertion signed) throws FederationException {
        requireNoUnknown(signed, "signed federation assertion");
        if (signed.getAssertion().isEmpty() || signed.getAssertion().size() > MAX_INNER_DOCUMENT_BYTES
                || signed.getSourceKeyIdSha256().size() != SHA256_BYTES
                || signed.getSignature().size() != ED25519_SIGNATURE_BYTES) {
            throw new FederationException("invalid signed federation assertion fields");
        }
    }

    private static void validateBindings(
            String source, String target, String player, byte[] clientKeyHash, String session,
            String assertionId, byte[] nonce, long issued, long expires, String policyVersion,
            byte[] policyHash, String disclosure, byte[] sourceKeyId, byte[] targetKeyId)
            throws FederationException {
        requireNetworkId(source, "source network id");
        requireNetworkId(target, "target network id");
        if (source.equals(target)) {
            throw new FederationException("source and target network ids must differ");
        }
        requirePlayerUuid(player);
        requireSha256(clientKeyHash, "client public-key hash");
        requireText(session, ProtocolConstants.MAX_FEDERATION_ID_CHARS, "authenticated session id");
        requireCanonicalUuid(assertionId, "assertion id");
        if (nonce.length != ProtocolConstants.NONCE_BYTES) {
            throw new FederationException("invalid assertion nonce length");
        }
        validateLifetime(issued, expires);
        requireText(policyVersion, ProtocolConstants.MAX_FEDERATION_ID_CHARS, "policy version");
        requireSha256(policyHash, "policy hash");
        requireSha256(sourceKeyId, "source network key id");
        requireSha256(targetKeyId, "target network key id");
        if (MessageDigest.isEqual(sourceKeyId, targetKeyId)) {
            throw new FederationException("source and target network identity keys must differ");
        }
        if (!MINIMAL_DISCLOSURE.equals(disclosure)) {
            throw new FederationException("federation disclosure is not the minimal supported claim");
        }
    }

    private static void validateRequestAtTime(
            FederationConsentRequest request, Clock clock, Duration allowedClockSkew) throws FederationException {
        validateRequest(request);
        Objects.requireNonNull(clock, "clock");
        validateAtTime(request.getIssuedAtEpochMs(), request.getExpiresAtEpochMs(),
                clock.millis(), validClockSkew(allowedClockSkew));
    }

    private static void validateAtTime(long issued, long expires, long now, long skew) throws FederationException {
        if (issued > safeAdd(now, skew, "federation clock comparison overflow")) {
            throw new FederationException("federation assertion was issued in the future");
        }
        // Clock skew only tolerates a slightly future issuedAt value.  A signed
        // expiration is an authorization boundary and is never extended by skew.
        if (expires <= now) {
            throw new FederationException("federation assertion has expired");
        }
    }

    private static void requireSameBindings(
            FederationConsentRequest request, ClientFederationConsent consent) throws FederationException {
        if (!consentFrom(request).build().equals(consent.toBuilder().clearClientSignature().build())) {
            throw new FederationException("client consent does not match its request");
        }
    }

    private static void requireSameBindings(
            FederationAssertion assertion, ClientFederationConsent consent) throws FederationException {
        if (assertion.getSchemaVersion() != consent.getSchemaVersion()
                || !assertion.getSourceNetworkId().equals(consent.getSourceNetworkId())
                || !assertion.getTargetNetworkId().equals(consent.getTargetNetworkId())
                || !assertion.getPlayerUuid().equals(consent.getPlayerUuid())
                || !assertion.getClientPublicKeySha256().equals(consent.getClientPublicKeySha256())
                || !assertion.getLocalAuthenticatedSessionId().equals(consent.getLocalAuthenticatedSessionId())
                || !assertion.getAssertionId().equals(consent.getAssertionId())
                || !assertion.getAssertionNonce().equals(consent.getAssertionNonce())
                || assertion.getIssuedAtEpochMs() != consent.getIssuedAtEpochMs()
                || assertion.getExpiresAtEpochMs() != consent.getExpiresAtEpochMs()
                || !assertion.getPolicyVersion().equals(consent.getPolicyVersion())
                || !assertion.getPolicySha256().equals(consent.getPolicySha256())
                || !assertion.getDisclosure().equals(consent.getDisclosure())
                || !assertion.getSourceKeyIdSha256().equals(consent.getSourceKeyIdSha256())
                || !assertion.getTargetKeyIdSha256().equals(consent.getTargetKeyIdSha256())) {
            throw new FederationException("client consent and source assertion bindings differ");
        }
    }

    private static void verifyClientSignature(ClientFederationConsent consent, PublicKey clientPublicKey)
            throws FederationException {
        if (!MessageDigest.isEqual(keyId(clientPublicKey), consent.getClientPublicKeySha256().toByteArray())) {
            throw new FederationException("client consent public-key hash mismatch");
        }
        ClientFederationConsent unsigned = consent.toBuilder().clearClientSignature().build();
        if (!verifySignature(signatureBytes(CLIENT_SIGNATURE_DOMAIN, unsigned.toByteArray()),
                consent.getClientSignature().toByteArray(), clientPublicKey)) {
            throw new FederationException("invalid client federation consent signature");
        }
    }

    private static void requireVersion(int version) throws FederationException {
        if (version != ProtocolConstants.FEDERATION_SCHEMA_VERSION) {
            throw new FederationException("unsupported federation schema version");
        }
    }

    private static void requireNetworkId(String value, String name) throws FederationException {
        requireText(value, ProtocolConstants.MAX_FEDERATION_ID_CHARS, name);
        if (!value.matches("[A-Za-z0-9][A-Za-z0-9._:-]*")) {
            throw new FederationException("invalid " + name);
        }
    }

    private static void requirePlayerUuid(String value) throws FederationException {
        requireCanonicalUuid(value, "player uuid");
    }

    private static void requireCanonicalUuid(String value, String name) throws FederationException {
        requireText(value, 36, name);
        try {
            if (!UUID.fromString(value).toString().equals(value)) {
                throw new FederationException("non-canonical " + name);
            }
        } catch (IllegalArgumentException exception) {
            throw new FederationException("invalid " + name, exception);
        }
    }

    private static void requireText(String value, int maximum, String name) throws FederationException {
        if (value == null || value.isBlank() || value.length() > maximum
                || value.codePoints().anyMatch(Character::isISOControl)) {
            throw new FederationException("invalid " + name);
        }
    }

    private static void requireSha256(byte[] value, String name) throws FederationException {
        if (value == null || value.length != SHA256_BYTES) {
            throw new FederationException("invalid " + name);
        }
    }

    private static void validateLifetime(long issued, long expires) throws FederationException {
        long lifetime;
        try {
            lifetime = Math.subtractExact(expires, issued);
        } catch (ArithmeticException exception) {
            throw new FederationException("invalid federation lifetime", exception);
        }
        if (issued <= 0L || lifetime <= 0L
                || lifetime > ProtocolConstants.MAX_FEDERATION_ASSERTION_TTL.toMillis()) {
            throw new FederationException("federation lifetime is outside the allowed range");
        }
    }

    private static long validLifetime(Duration lifetime) throws FederationException {
        Objects.requireNonNull(lifetime, "lifetime");
        long millis = lifetime.toMillis();
        if (lifetime.isNegative() || lifetime.isZero() || millis <= 0L
                || millis > ProtocolConstants.MAX_FEDERATION_ASSERTION_TTL.toMillis()) {
            throw new FederationException("federation lifetime is outside the allowed range");
        }
        return millis;
    }

    private static long validClockSkew(Duration skew) throws FederationException {
        Objects.requireNonNull(skew, "allowedClockSkew");
        if (skew.isNegative()) {
            throw new FederationException("allowed clock skew must not be negative");
        }
        long millis;
        try {
            millis = skew.toMillis();
        } catch (ArithmeticException exception) {
            throw new FederationException("allowed clock skew overflows milliseconds", exception);
        }
        if (millis > ProtocolConstants.DEFAULT_CLOCK_SKEW.toMillis()) {
            throw new FederationException("allowed clock skew exceeds federation maximum");
        }
        return millis;
    }

    private static void requireInnerBudget(Message document, String name) throws FederationException {
        if (document.getSerializedSize() > MAX_INNER_DOCUMENT_BYTES) {
            throw new FederationException(name + " exceeds encoded budget");
        }
    }

    private static void requireNoUnknown(Message document, String name) throws FederationException {
        if (!document.getUnknownFields().asMap().isEmpty()) {
            throw new FederationException(name + " contains unknown fields");
        }
    }

    private static PublicKey decodeClientPublicKey(byte[] encoded) throws FederationException {
        if (encoded.length == 0 || encoded.length > MAX_CLIENT_PUBLIC_KEY_X509_BYTES) {
            throw new FederationException("invalid client public key size");
        }
        try {
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(encoded));
        } catch (GeneralSecurityException exception) {
            throw new FederationException("invalid client Ed25519 public key", exception);
        }
    }

    private static byte[] keyId(PublicKey publicKey) throws FederationException {
        Objects.requireNonNull(publicKey, "publicKey");
        return sha256(publicKey.getEncoded());
    }

    private static byte[] sha256(byte[] value) throws FederationException {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value);
        } catch (NoSuchAlgorithmException exception) {
            throw new FederationException("SHA-256 is unavailable", exception);
        }
    }

    private static byte[] signatureBytes(byte[] domain, byte[] document) {
        return ByteBuffer.allocate(domain.length + Integer.BYTES + document.length)
                .put(domain)
                .putInt(document.length)
                .put(document)
                .array();
    }

    private static byte[] sign(byte[] content, PrivateKey privateKey) throws FederationException {
        Objects.requireNonNull(privateKey, "privateKey");
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initSign(privateKey);
            signature.update(content);
            return signature.sign();
        } catch (GeneralSecurityException exception) {
            throw new FederationException("failed to sign federation document", exception);
        }
    }

    private static boolean verifySignature(byte[] content, byte[] signed, PublicKey publicKey)
            throws FederationException {
        try {
            Signature signature = Signature.getInstance("Ed25519");
            signature.initVerify(publicKey);
            signature.update(content);
            return signature.verify(signed);
        } catch (GeneralSecurityException exception) {
            throw new FederationException("failed to verify federation signature", exception);
        }
    }

    private static long safeAdd(long left, long right, String message) throws FederationException {
        try {
            return Math.addExact(left, right);
        } catch (ArithmeticException exception) {
            throw new FederationException(message, exception);
        }
    }

}
