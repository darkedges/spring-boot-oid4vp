package com.darkedges.oid4vp.core.request;

import com.fasterxml.jackson.databind.JsonNode;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Derives the response audience a Wallet is expected to bind its Verifiable Presentation to, from the
 * Verifier's own {@code client_id} (OpenID4VP 1.1, "Client Identifier Prefix and Verifier Metadata
 * Management"). For every prefix except {@code x509_san_dns} this is just the full client_id string
 * itself; for {@code x509_san_dns} the Wallet instead binds to {@code x509_hash:<base64url(sha256(leaf
 * cert DER)))>} of the certificate that signed the Request Object, since the DNS name alone isn't a
 * verifiable cryptographic binding.
 */
public final class ExpectedAudienceResolver {

    private ExpectedAudienceResolver() {}

    public static String resolve(ClientIdentifierPrefix clientId, RequestObjectSigningKeyResolver resolver, String registrationId) {
        if (!(clientId instanceof ClientIdentifierPrefix.X509SanDns)) {
            return clientId.fullClientId();
        }
        if (resolver == null) {
            throw new IllegalStateException("x509_san_dns requires requestObjectSigningKeyResolver to be configured");
        }
        JsonNode signingKey = resolver.resolveSigningKey(registrationId)
                .orElseThrow(() -> new IllegalStateException("no request-signing key found for registration \"" + registrationId + "\""));
        JsonNode x5c = signingKey.path("x5c");
        if (!x5c.isArray() || x5c.isEmpty()) {
            throw new IllegalStateException("request-signing key for \"" + registrationId + "\" has no x5c certificate chain");
        }
        byte[] der = Base64.getDecoder().decode(x5c.get(0).asText());
        return "x509_hash:" + Base64.getUrlEncoder().withoutPadding().encodeToString(sha256(der));
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
