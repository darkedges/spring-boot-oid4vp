package com.darkedges.oid4vp.spring.security.web;

import com.darkedges.oid4vp.core.dcql.DcqlQuery;
import com.darkedges.oid4vp.core.request.ClientIdentifierPrefix;

import java.io.Serializable;
import java.net.URI;
import java.time.Instant;
import java.util.Optional;

/**
 * The Verifier-side record of one Authorization Request that was sent to a Wallet, kept until the
 * {@code direct_post} response arrives (or the request expires). Correlated purely by {@code state} —
 * not the {@code HttpSession} — since the response POST typically originates from the Wallet's backend,
 * not the browser that carried the Verifier's session cookie.
 *
 * @param transactionId present only when the same-device {@code response_code}/{@code redirect_uri}
 *                       handoff (OpenID4VP 1.1, "Response Mode direct_post" reference design) is in use:
 *                       a secret known only to the Verifier's own frontend session (never sent to the
 *                       Wallet), used to retrieve the Authorization Response once it arrives.
 */
public record Oid4vpAuthorizationRequestContext(
        String registrationId,
        String state,
        String nonce,
        ClientIdentifierPrefix clientId,
        DcqlQuery dcqlQuery,
        URI responseUri,
        Instant expiresAt,
        Optional<String> transactionId) implements Serializable {

    public Oid4vpAuthorizationRequestContext {
        if (registrationId == null || state == null || nonce == null || clientId == null || dcqlQuery == null
                || responseUri == null || expiresAt == null) {
            throw new IllegalArgumentException("all fields of Oid4vpAuthorizationRequestContext are required");
        }
        transactionId = transactionId == null ? Optional.empty() : transactionId;
    }

    public Oid4vpAuthorizationRequestContext(
            String registrationId, String state, String nonce, ClientIdentifierPrefix clientId,
            DcqlQuery dcqlQuery, URI responseUri, Instant expiresAt) {
        this(registrationId, state, nonce, clientId, dcqlQuery, responseUri, expiresAt, Optional.empty());
    }

    public boolean isExpired(Instant now) {
        return now.isAfter(expiresAt);
    }
}
