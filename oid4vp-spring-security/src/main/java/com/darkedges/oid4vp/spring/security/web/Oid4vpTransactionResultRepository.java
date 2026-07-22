package com.darkedges.oid4vp.spring.security.web;

import org.springframework.security.core.Authentication;

import java.util.Optional;

/**
 * Stores the outcome of a validated Authorization Response, keyed by {@code transactionId}, for the
 * Verifier's own frontend session to retrieve — the {@code response_code}/{@code redirect_uri} same-device
 * handoff (OpenID4VP 1.1, "Response Mode direct_post" reference design).
 */
public interface Oid4vpTransactionResultRepository {

    void save(String transactionId, String responseCode, Authentication authentication);

    /** Loads and removes (single-use) the result, and only returns it if {@code responseCode} matches
     * what was stored — this is the check that ensures only the party who received the redirect (i.e.
     * the End-User's browser, sent there by the Wallet) can retrieve the Authorization Response data. */
    Optional<Authentication> consume(String transactionId, String responseCode);
}
