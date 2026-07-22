package com.darkedges.oid4vp.core.response;

import com.darkedges.oid4vp.core.dcql.CredentialQuery;

import java.time.Clock;

/**
 * Parameters a {@link PresentationVerifier} needs to verify one presentation against the Authorization
 * Request it is answering.
 *
 * @param query            the Credential Query this presentation is claimed to satisfy (for
 *                         {@code require_cryptographic_holder_binding} and {@code meta} re-checks).
 * @param expectedNonce    the Authorization Request's {@code nonce}.
 * @param expectedAudience the full Client Identifier (or {@code origin:<origin>} for the Digital
 *                         Credentials API) the presentation must be bound to.
 * @param issuerKeyResolver resolves the issuer's public key.
 * @param clock            injectable clock, so expiry checks are reproducible in tests.
 */
public record PresentationVerificationParams(
        CredentialQuery query,
        String expectedNonce,
        String expectedAudience,
        IssuerKeyResolver issuerKeyResolver,
        Clock clock) {

    public PresentationVerificationParams {
        if (query == null || expectedNonce == null || expectedAudience == null || issuerKeyResolver == null) {
            throw new IllegalArgumentException("query, expectedNonce, expectedAudience, and issuerKeyResolver are required");
        }
        clock = clock == null ? Clock.systemUTC() : clock;
    }
}
