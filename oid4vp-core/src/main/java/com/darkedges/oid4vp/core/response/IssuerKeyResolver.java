package com.darkedges.oid4vp.core.response;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.List;
import java.util.Optional;

/**
 * Resolves the public key (as a raw JWK JSON object) that should have signed a Credential/presentation
 * from a given issuer, keyed by an optional JOSE {@code kid}. Kept crypto-library-agnostic here (this
 * module has no JOSE dependency); format modules parse the returned JWK with whichever library they use.
 */
public interface IssuerKeyResolver {

    /**
     * @param certificateChain the credential's own {@code x5c} JWS header value, if present — base64
     *                         (standard, not URL-safe) DER-encoded X.509 certificates, leaf-first
     *                         (RFC7515 §4.1.6), empty when absent. Lets a resolver trust a self-signed
     *                         issuer directly from the credential itself, without needing external key
     *                         discovery.
     */
    Optional<JsonNode> resolve(String issuer, Optional<String> keyId, List<String> certificateChain);
}
