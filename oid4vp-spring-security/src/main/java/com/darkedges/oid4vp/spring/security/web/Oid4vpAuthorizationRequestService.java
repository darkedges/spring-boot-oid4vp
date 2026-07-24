package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.request.AuthorizationRequest;
import com.darkedges.oid4vp.core.request.ClientMetadata;
import com.darkedges.oid4vp.core.request.ResponseMode;
import com.darkedges.oid4vp.spring.security.registration.CodeFlowConfig;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistration;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistrationRepository;
import com.darkedges.oid4vp.verifier.encryption.EphemeralEncryptionKeyGenerator;
import com.darkedges.oid4vp.verifier.encryption.EphemeralEncryptionKeyPair;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Builds a fresh {@link AuthorizationRequest} for a relying-party registration: generates a
 * cryptographically random {@code nonce}/{@code state} (≥128 bits of entropy each, per OpenID4VP 1.1),
 * and persists the correlating {@link Oid4vpAuthorizationRequestContext} so the response endpoint can
 * later resolve it.
 *
 * <p>When the registration has a {@link CodeFlowConfig} ({@code registration.codeFlow()}), builds a
 * {@code response_type=code} request instead of the default {@code vp_token} one: PKCE
 * {@code code_verifier}/{@code code_challenge} are generated here, the verifier is kept server-side in
 * the saved {@link Oid4vpAuthorizationRequestContext} (never sent to the Wallet), and the request carries
 * {@code redirect_uri}/{@code code_challenge} instead of {@code response_uri}.
 */
public final class Oid4vpAuthorizationRequestService {

    // 256 bits: comfortably above OpenID4VP's 128-bit nonce-entropy floor (OpenID4VP PR #722) — a single
    // 128-bit sample's measured Shannon entropy can read as "insufficient" on some conformance checks
    // purely from per-sample variance, so this leaves margin rather than sitting exactly on the minimum.
    private static final int TOKEN_BYTES = 32; // 256 bits
    private static final int CODE_VERIFIER_BYTES = 32; // -> 43 base64url chars, within RFC 7636's 43-128 range

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Oid4vpRelyingPartyRegistrationRepository registrations;
    private final Oid4vpAuthorizationRequestRepository requestRepository;
    private final Oid4vpEphemeralEncryptionKeyRepository ephemeralEncryptionKeyRepository;
    private final Clock clock;
    private final Duration requestTtl;
    private final SecureRandom random = new SecureRandom();

    public Oid4vpAuthorizationRequestService(
            Oid4vpRelyingPartyRegistrationRepository registrations,
            Oid4vpAuthorizationRequestRepository requestRepository,
            Oid4vpEphemeralEncryptionKeyRepository ephemeralEncryptionKeyRepository,
            Clock clock,
            Duration requestTtl) {
        this.registrations = registrations;
        this.requestRepository = requestRepository;
        this.ephemeralEncryptionKeyRepository = ephemeralEncryptionKeyRepository;
        this.clock = clock;
        this.requestTtl = requestTtl;
    }

    public Oid4vpAuthorizationRequestResolution resolve(String registrationId) {
        Oid4vpRelyingPartyRegistration registration = registrations.findByRegistrationId(registrationId)
                .orElseThrow(() -> new IllegalArgumentException("unknown relying party registration: " + registrationId));

        String nonce = randomUrlSafeToken();
        String state = randomUrlSafeToken();
        String transactionId = randomUrlSafeToken();
        DcqlQuery dcqlQuery = registration.dcqlQuery().get();
        Optional<CodeFlowConfig> codeFlow = registration.codeFlow();

        AuthorizationRequest request;
        Optional<String> codeVerifier = Optional.empty();

        if (codeFlow.isPresent()) {
            String verifier = generateCodeVerifier();
            codeVerifier = Optional.of(verifier);
            request = new AuthorizationRequest(
                    "code",
                    registration.clientId(),
                    ResponseMode.QUERY,
                    Optional.empty(),
                    Optional.of(codeFlow.get().redirectUri().toString()),
                    Optional.of(dcqlQuery),
                    Optional.empty(),
                    Optional.of(state),
                    nonce,
                    registration.clientMetadata(),
                    registration.requestUriMethod(),
                    List.of(),
                    registration.verifierInfo(),
                    Optional.of(deriveCodeChallengeS256(verifier)),
                    Optional.of("S256"));
        } else {
            request = new AuthorizationRequest(
                    "vp_token",
                    registration.clientId(),
                    registration.responseMode(),
                    Optional.of(registration.responseUri().toString()),
                    Optional.empty(),
                    Optional.of(dcqlQuery),
                    Optional.empty(),
                    Optional.of(state),
                    nonce,
                    clientMetadataFor(registration, registrationId),
                    registration.requestUriMethod(),
                    List.of(),
                    registration.verifierInfo(),
                    Optional.empty(),
                    Optional.empty());
        }

        requestRepository.save(new Oid4vpAuthorizationRequestContext(
                registrationId, state, nonce, registration.clientId(), dcqlQuery, registration.responseUri(),
                clock.instant().plus(requestTtl), Optional.of(transactionId), codeVerifier));

        return new Oid4vpAuthorizationRequestResolution(request, transactionId);
    }

    /**
     * For {@code direct_post.jwt}/{@code dc_api.jwt} registrations, generates a fresh response-encryption
     * keypair for <em>this</em> request, saves the private half so it can be found later, and returns
     * {@code client_metadata} with its {@code jwks} replaced by the public half — HAIP forbids reusing the
     * same response-encryption key across Authorization Requests. Every other response mode returns the
     * registration's static {@code client_metadata} unchanged.
     */
    private Optional<ClientMetadata> clientMetadataFor(Oid4vpRelyingPartyRegistration registration, String registrationId) {
        ResponseMode responseMode = registration.responseMode();
        if (responseMode != ResponseMode.DIRECT_POST_JWT && responseMode != ResponseMode.DC_API_JWT) {
            return registration.clientMetadata();
        }

        ClientMetadata staticMetadata = registration.clientMetadata()
                .orElseThrow(() -> new IllegalStateException(
                        "registration \"" + registrationId + "\" uses " + responseMode.value()
                                + " but has no client-metadata configured (needed for vp_formats_supported etc.)"));

        EphemeralEncryptionKeyPair keyPair = EphemeralEncryptionKeyGenerator.generate();
        ephemeralEncryptionKeyRepository.save(registrationId, keyPair.privateJwk(), clock.instant().plus(requestTtl));

        ObjectNode jwks = MAPPER.createObjectNode();
        jwks.putArray("keys").add(keyPair.publicJwk());

        return Optional.of(new ClientMetadata(
                Optional.of(jwks), staticMetadata.encryptedResponseEncValuesSupported(), staticMetadata.vpFormatsSupported()));
    }

    private String randomUrlSafeToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String generateCodeVerifier() {
        byte[] bytes = new byte[CODE_VERIFIER_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String deriveCodeChallengeS256(String codeVerifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
