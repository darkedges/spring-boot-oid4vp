package com.darkedges.oid4vp.spring.security.web;

import java.util.Optional;

/**
 * Stores {@link Oid4vpAuthorizationRequestContext}s between issuing an Authorization Request and
 * receiving its {@code direct_post} response, keyed by {@code state}.
 *
 * <p>Unlike Spring Security's typical {@code AuthorizationRequestRepository} (session-based), this is
 * deliberately <em>not</em> tied to the {@code HttpSession}: the response POST commonly arrives from the
 * Wallet's backend, which does not carry the Verifier browser session's cookie.
 */
public interface Oid4vpAuthorizationRequestRepository {

    void save(Oid4vpAuthorizationRequestContext context);

    /** Loads and removes (single-use) the context for the given {@code state}, so a given {@code state}
     * cannot be replayed against the response endpoint. */
    Optional<Oid4vpAuthorizationRequestContext> consume(String state);
}
