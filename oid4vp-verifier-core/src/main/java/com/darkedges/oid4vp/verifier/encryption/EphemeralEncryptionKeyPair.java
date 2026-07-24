package com.darkedges.oid4vp.verifier.encryption;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * A freshly generated response-encryption keypair: {@code publicJwk} is what goes into an Authorization
 * Request's {@code client_metadata.jwks}, {@code privateJwk} is what a {@code ResponseDecryptionKeyResolver}
 * later needs to decrypt that specific request's response. Both carry the same {@code kid}.
 */
public record EphemeralEncryptionKeyPair(JsonNode publicJwk, JsonNode privateJwk) {

    public EphemeralEncryptionKeyPair {
        if (publicJwk == null || privateJwk == null) {
            throw new IllegalArgumentException("publicJwk and privateJwk are required");
        }
    }
}
