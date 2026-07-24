package com.darkedges.oid4vp.wallet;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.Clock;
import java.util.Optional;

/**
 * Parameters a {@link PresentationBuilder} needs to build one presentation in response to an
 * Authorization Request.
 *
 * @param nonce               the Authorization Request's {@code nonce}.
 * @param audience            the full Client Identifier (or {@code origin:<origin>} for the Digital
 *                            Credentials API) the presentation must be bound to.
 * @param clientId            the literal {@code client_id}, distinct from {@code audience} — mdoc's
 *                            {@code OpenID4VPHandover} hashes this raw value, not the derived
 *                            response-audience, so the two are kept separate the same way the
 *                            Verifier-side {@code PresentationVerificationParams} does.
 * @param responseUri         the Authorization Request's {@code response_uri} — the other half of
 *                            {@code OpenID4VPHandover}.
 * @param responseEncryptionPublicJwk the Verifier's response-encryption public key (from
 *                            {@code client_metadata.jwks}, raw JSON, kept crypto-library-agnostic) this
 *                            response will be encrypted to — mdoc's {@code OpenID4VPHandover} hashes its
 *                            RFC 7638 thumbprint; empty for an unencrypted response, which no mdoc
 *                            presentation can use.
 * @param holderKeyResolver   resolves the signer for a credential's Holder Binding key.
 * @param clock               injectable clock, so timestamps are reproducible in tests.
 */
public record PresentationBuildParams(
        String nonce,
        String audience,
        String clientId,
        String responseUri,
        Optional<JsonNode> responseEncryptionPublicJwk,
        HolderKeyResolver holderKeyResolver,
        Clock clock) {

    public PresentationBuildParams {
        if (nonce == null || audience == null || clientId == null || responseUri == null || holderKeyResolver == null) {
            throw new IllegalArgumentException("nonce, audience, clientId, responseUri, and holderKeyResolver are required");
        }
        responseEncryptionPublicJwk = responseEncryptionPublicJwk == null ? Optional.empty() : responseEncryptionPublicJwk;
        clock = clock == null ? Clock.systemUTC() : clock;
    }
}
