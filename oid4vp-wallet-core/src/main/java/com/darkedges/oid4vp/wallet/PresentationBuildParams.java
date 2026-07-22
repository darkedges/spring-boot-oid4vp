package com.darkedges.oid4vp.wallet;

import java.time.Clock;

/**
 * Parameters a {@link PresentationBuilder} needs to build one presentation in response to an
 * Authorization Request.
 *
 * @param nonce             the Authorization Request's {@code nonce}.
 * @param audience          the full Client Identifier (or {@code origin:<origin>} for the Digital
 *                          Credentials API) the presentation must be bound to.
 * @param holderKeyResolver resolves the signer for a credential's Holder Binding key.
 * @param clock             injectable clock, so timestamps are reproducible in tests.
 */
public record PresentationBuildParams(String nonce, String audience, HolderKeyResolver holderKeyResolver, Clock clock) {

    public PresentationBuildParams {
        if (nonce == null || audience == null || holderKeyResolver == null) {
            throw new IllegalArgumentException("nonce, audience, and holderKeyResolver are required");
        }
        clock = clock == null ? Clock.systemUTC() : clock;
    }
}
