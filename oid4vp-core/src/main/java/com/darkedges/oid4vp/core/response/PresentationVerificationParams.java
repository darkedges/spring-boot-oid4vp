package com.darkedges.oid4vp.core.response;

import com.darkedges.oid4vp.core.dcql.CredentialQuery;
import com.fasterxml.jackson.databind.JsonNode;

import java.time.Clock;
import java.util.Optional;

/**
 * Parameters a {@link PresentationVerifier} needs to verify one presentation against the Authorization
 * Request it is answering.
 *
 * @param query            the Credential Query this presentation is claimed to satisfy (for
 *                         {@code require_cryptographic_holder_binding} and {@code meta} re-checks).
 * @param expectedNonce    the Authorization Request's {@code nonce}.
 * @param expectedAudience the full Client Identifier (or {@code origin:<origin>} for the Digital
 *                         Credentials API) the presentation must be bound to.
 * @param clientId         the Verifier's own raw {@code client_id}, exactly as sent in the Authorization
 *                         Request. Distinct from {@code expectedAudience}: for most formats/schemes they
 *                         happen to be the same string, but mdoc's {@code OpenID4VPHandover} hashes the
 *                         literal {@code client_id}, not whatever derived value a Wallet binds its
 *                         response audience to (e.g. {@code x509_hash:...} for {@code x509_san_dns}).
 * @param responseUri      the Authorization Request's {@code response_uri} — also hashed into mdoc's
 *                         {@code OpenID4VPHandover}.
 * @param responseEncryptionPublicJwk the public JWK (as raw JSON, kept crypto-library-agnostic like
 *                         {@link IssuerKeyResolver}'s return type) of the response-encryption key this
 *                         response was actually encrypted to — mdoc's {@code OpenID4VPHandover} hashes its
 *                         RFC 7638 thumbprint (both sides derive it independently from a key they already
 *                         have; per spec, {@code null} when the response is unencrypted). Empty for
 *                         non-mdoc presentations or unencrypted responses.
 * @param issuerKeyResolver resolves the issuer's public key.
 * @param clock            injectable clock, so expiry checks are reproducible in tests.
 */
public record PresentationVerificationParams(
        CredentialQuery query,
        String expectedNonce,
        String expectedAudience,
        String clientId,
        String responseUri,
        Optional<JsonNode> responseEncryptionPublicJwk,
        IssuerKeyResolver issuerKeyResolver,
        Clock clock) {

    public PresentationVerificationParams {
        if (query == null || expectedNonce == null || expectedAudience == null || clientId == null
                || responseUri == null || issuerKeyResolver == null) {
            throw new IllegalArgumentException(
                    "query, expectedNonce, expectedAudience, clientId, responseUri, and issuerKeyResolver are required");
        }
        responseEncryptionPublicJwk = responseEncryptionPublicJwk == null ? Optional.empty() : responseEncryptionPublicJwk;
        clock = clock == null ? Clock.systemUTC() : clock;
    }
}
