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

    /**
     * Loads and removes the context for {@code state} only if it was issued for {@code registrationId}: a response for one relying
     * party must never be accepted at another's endpoint (or, in the code flow, be exchanged with another's token endpoint and
     * client_id). A {@code state} presented at the wrong registration is not returned.
     *
     * <p>Implementations should check and remove atomically, so a {@code state} presented at the wrong endpoint is left untouched
     * and cannot be used to burn a genuine transaction. This default, for implementations that predate it, consumes first and then
     * checks: still safe (the mismatch is refused), but the genuine response can then no longer complete.
     */
    default Optional<Oid4vpAuthorizationRequestContext> consume(String state, String registrationId) {
        return consume(state).filter(context -> context.registrationId().equals(registrationId));
    }
}
