package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.request.AuthorizationRequest;
import com.darkedges.oid4vp.core.request.RequestUriMethod;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistration;
import com.darkedges.oid4vp.spring.security.registration.Oid4vpRelyingPartyRegistrationRepository;

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
 */
public final class Oid4vpAuthorizationRequestService {

    private static final int TOKEN_BYTES = 16; // 128 bits

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

        AuthorizationRequest request = new AuthorizationRequest(
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
                registration.verifierInfo());

        requestRepository.save(new Oid4vpAuthorizationRequestContext(
                registrationId, state, nonce, registration.clientId(), dcqlQuery, registration.responseUri(),
                clock.instant().plus(requestTtl), Optional.of(transactionId)));

        return new Oid4vpAuthorizationRequestResolution(request, transactionId);
    }

    private String randomUrlSafeToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
