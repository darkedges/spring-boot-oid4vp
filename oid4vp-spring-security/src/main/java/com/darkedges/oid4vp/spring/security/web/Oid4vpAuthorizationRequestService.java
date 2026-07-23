package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.request.AuthorizationRequest;
import com.darkedges.oid4vp.core.request.RequestUriMethod;
import com.darkedges.oid4vp.core.request.ResponseMode;
import com.darkedges.oid4vp.spring.security.registration.CodeFlowConfig;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistration;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistrationRepository;

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

    private static final int TOKEN_BYTES = 16; // 128 bits
    private static final int CODE_VERIFIER_BYTES = 32; // -> 43 base64url chars, within RFC 7636's 43-128 range

    private final Oid4vpRelyingPartyRegistrationRepository registrations;
    private final Oid4vpAuthorizationRequestRepository requestRepository;
    private final Clock clock;
    private final Duration requestTtl;
    private final SecureRandom random = new SecureRandom();

    public Oid4vpAuthorizationRequestService(
            Oid4vpRelyingPartyRegistrationRepository registrations,
            Oid4vpAuthorizationRequestRepository requestRepository,
            Clock clock,
            Duration requestTtl) {
        this.registrations = registrations;
        this.requestRepository = requestRepository;
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
                    RequestUriMethod.GET,
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
                    registration.clientMetadata(),
                    RequestUriMethod.GET,
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
