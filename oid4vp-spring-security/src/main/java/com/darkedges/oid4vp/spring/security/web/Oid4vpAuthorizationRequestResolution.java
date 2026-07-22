package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.request.AuthorizationRequest;

/**
 * The result of {@link Oid4vpAuthorizationRequestService#resolve(String)}: the request to send the
 * Wallet, plus a {@code transactionId} for the Verifier's own frontend session to hold onto (never sent
 * to the Wallet) if it wants to use the {@code response_code}/{@code redirect_uri} same-device handoff.
 */
public record Oid4vpAuthorizationRequestResolution(AuthorizationRequest request, String transactionId) {

    public Oid4vpAuthorizationRequestResolution {
        if (request == null || transactionId == null || transactionId.isBlank()) {
            throw new IllegalArgumentException("request and transactionId are required");
        }
    }
}
